use std::{
    ffi::{CStr, OsStr},
    os::{raw::c_char, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use libc::CLOCK_REALTIME;
use serde::Serialize;

use fact_ebpf::{PATH_MAX, event_t, fact_event_type_t, inode_key_t, process_t};

use crate::{
    event::network::{NetworkData, SocketData, SocketTuple},
    host_info,
};
use process::Process;

mod network;
pub mod process;

fn slice_to_string(s: &[c_char]) -> anyhow::Result<String> {
    Ok(unsafe { CStr::from_ptr(s.as_ptr()) }.to_str()?.to_owned())
}

/// Sanitize a buffer obtained from calling d_path kernel side.
///
/// Sanitizing this type of buffer is a special case, because the kernel
/// may append " (deleted)" to a path when the file has been removed and
/// can mess with the event we report. This method will take a slice of
/// c_char and return a PathBuf with the " (deleted)" portion removed.
///
/// With the current implementation, non UTF-8 characters in the file
/// name will be replaced with the U+FFFD character.
///
/// Note that no special check is made for the case in which a file name
/// actually ends with the " (deleted)" suffix. This means that if we
/// would get an event on a file named `/etc/something/file\ (deleted)`,
/// we would wrongly report the file name as `/etc/something/file`.
/// However, we believe this would be a _very_ special case with a low
/// chance that we will stumble upon it, so we purposely decide to
/// ignore it.
fn sanitize_d_path(s: &[c_char]) -> PathBuf {
    let s = unsafe { CStr::from_ptr(s.as_ptr()) };
    let p = Path::new(OsStr::from_bytes(s.to_bytes()));

    // Take the file name of the path and remove the " (deleted)" suffix
    // if present.
    if let Some(file_name) = p.file_name()
        && let Some(file_name) = file_name.to_string_lossy().strip_suffix(" (deleted)")
    {
        // The file name needed to be sanitized
        return p.parent().map(|p| p.join(file_name)).unwrap_or_default();
    }

    p.to_path_buf()
}

fn timestamp_to_proto(ts: u64) -> prost_types::Timestamp {
    let seconds = (ts / 1_000_000_000) as i64;
    let nanos = (ts % 1_000_000_000) as i32;
    prost_types::Timestamp { seconds, nanos }
}

fn proto_to_timestamp(prost_types::Timestamp { seconds, nanos }: prost_types::Timestamp) -> u64 {
    (seconds * 1_000_000_000) as u64 + nanos as u64
}

#[derive(Debug)]
pub enum EventTestData {
    Creation,
    Unlink,
    Chmod(u16, u16),
    Rename(PathBuf),
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: String,
    pub data: EventData,
}

impl Event {
    pub fn new(
        data: EventTestData,
        hostname: &'static str,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as _;
        let inner = BaseFileData {
            filename,
            host_file,
            inode: Default::default(),
        };
        let file = match data {
            EventTestData::Creation => FileData::Creation(inner),
            EventTestData::Unlink => FileData::Unlink(inner),
            EventTestData::Chmod(new_mode, old_mode) => {
                let data = ChmodFileData {
                    inner,
                    new_mode,
                    old_mode,
                };
                FileData::Chmod(data)
            }
            EventTestData::Rename(old_path) => {
                let data = RenameFileData {
                    new: inner,
                    old: BaseFileData {
                        filename: old_path,
                        ..Default::default()
                    },
                };
                FileData::Rename(data)
            }
        };

        let data = EventData::File { process, file };

        Ok(Event {
            timestamp,
            hostname: hostname.to_string(),
            data,
        })
    }

    /// Unwrap the inner FileData and return the inode that triggered
    /// the event.
    ///
    /// In the case of operations that involve two inodes, like rename,
    /// the 'new' inode will be returned.
    pub fn get_inode(&self) -> Option<&inode_key_t> {
        match &self.data {
            EventData::File {
                file: FileData::Open(data),
                ..
            } => Some(&data.inode),
            EventData::File {
                file: FileData::Creation(data),
                ..
            } => Some(&data.inode),
            EventData::File {
                file: FileData::Unlink(data),
                ..
            } => Some(&data.inode),
            EventData::File {
                file: FileData::Chmod(data),
                ..
            } => Some(&data.inner.inode),
            EventData::File {
                file: FileData::Chown(data),
                ..
            } => Some(&data.inner.inode),
            EventData::File {
                file: FileData::Rename(data),
                ..
            } => Some(&data.new.inode),
            EventData::Process(_) | EventData::Network { .. } => None,
        }
    }

    /// Same as `get_inode` but returning the 'old' inode for operations
    /// like rename. For operations that involve a single inode, `None`
    /// will be returned.
    pub fn get_old_inode(&self) -> Option<&inode_key_t> {
        match &self.data {
            EventData::File {
                file: FileData::Rename(data),
                ..
            } => Some(&data.old.inode),
            _ => None,
        }
    }

    /// Set the `host_file` field of the event to the one provided.
    ///
    /// In the case of operations that involve two paths, like rename,
    /// the 'new' host_file will be set.
    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.data {
            EventData::File {
                file: FileData::Open(data),
                ..
            } => data.host_file = host_path,
            EventData::File {
                file: FileData::Creation(data),
                ..
            } => data.host_file = host_path,
            EventData::File {
                file: FileData::Unlink(data),
                ..
            } => data.host_file = host_path,
            EventData::File {
                file: FileData::Chmod(data),
                ..
            } => data.inner.host_file = host_path,
            EventData::File {
                file: FileData::Chown(data),
                ..
            } => data.inner.host_file = host_path,
            EventData::File {
                file: FileData::Rename(data),
                ..
            } => data.new.host_file = host_path,
            EventData::Process(_) | EventData::Network { .. } => {}
        }
    }

    /// Same as `set_host_path` but setting the 'old' host_file for
    /// operations that have one, like rename.
    pub fn set_old_host_path(&mut self, host_path: PathBuf) {
        if let EventData::File {
            file: FileData::Rename(data),
            ..
        } = &mut self.data
        {
            data.old.host_file = host_path
        }
    }

    pub fn is_file_event(&self) -> bool {
        matches!(self.data, EventData::File { .. })
    }

    pub fn is_process_event(&self) -> bool {
        matches!(self.data, EventData::Process(_))
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let data = EventData::try_from(value)?;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname().to_string(),
            data,
        })
    }
}

impl TryFrom<&process_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &process_t) -> Result<Self, Self::Error> {
        let timestamp = host_info::get_clock(CLOCK_REALTIME);
        let data = EventData::try_from(*value)?;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname().to_string(),
            data,
        })
    }
}

impl From<Event> for fact_api::FactMsg {
    fn from(value: Event) -> Self {
        let timestamp = timestamp_to_proto(value.timestamp);
        Self {
            timestamp: Some(timestamp),
            hostname: value.hostname.to_string(),
            msg: Some(value.data.into()),
        }
    }
}

impl From<fact_api::FactMsg> for Event {
    fn from(
        fact_api::FactMsg {
            timestamp,
            hostname,
            msg,
        }: fact_api::FactMsg,
    ) -> Self {
        match msg {
            Some(data) => Event {
                timestamp: proto_to_timestamp(timestamp.expect("Empty timestamp received")),
                hostname,
                data: data.into(),
            },
            None => unreachable!(),
        }
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.data == other.data
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum EventData {
    File {
        process: Process,
        file: FileData,
    },
    Process(ProcessData),
    Network {
        process: Process,
        network: NetworkData,
    },
}

impl TryFrom<&event_t> for EventData {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let process = Process::try_from(value.process)?;
        let data = match value.type_ {
            fact_event_type_t::FILE_ACTIVITY_OPEN
            | fact_event_type_t::FILE_ACTIVITY_CREATION
            | fact_event_type_t::FILE_ACTIVITY_UNLINK
            | fact_event_type_t::FILE_ACTIVITY_CHMOD
            | fact_event_type_t::FILE_ACTIVITY_CHOWN
            | fact_event_type_t::FILE_ACTIVITY_RENAME => EventData::File {
                file: FileData::new(
                    value.type_,
                    unsafe { value.common_data.file.path },
                    unsafe { value.common_data.file.inode },
                    value.__bindgen_anon_1,
                )?,
                process,
            },
            fact_event_type_t::PROCESS_FORK => {
                let child = Process::try_from(value.process)?;
                let data = ProcessForkData { child };
                EventData::Process(ProcessData::Fork(data))
            }
            fact_event_type_t::PROCESS_EXEC => {
                let proc = Process::try_from(value.process)?;
                let data = ProcessExecData(proc);
                EventData::Process(ProcessData::Exec(data))
            }
            fact_event_type_t::PROCESS_EXIT => {
                let proc = Process::try_from(value.process)?;
                let data = ProcessExitData(proc);
                EventData::Process(ProcessData::Exit(data))
            }
            fact_event_type_t::SOCKET_LISTEN => {
                let socket = SocketData::new(
                    unsafe { value.common_data.network.__bindgen_anon_1.listen },
                    unsafe { value.common_data.network.family },
                );
                let socket = NetworkData::Listen(socket);
                EventData::Network {
                    process,
                    network: socket,
                }
            }
            fact_event_type_t::SOCKET_ACCEPT => {
                let data = SocketTuple::new(
                    unsafe { value.common_data.network.__bindgen_anon_1.accept },
                    unsafe { value.common_data.network.family },
                );
                let data = NetworkData::Accept(data);
                EventData::Network {
                    process,
                    network: data,
                }
            }
            fact_event_type_t::SOCKET_CONNECT => {
                let data = SocketTuple::new(
                    unsafe { value.common_data.network.__bindgen_anon_1.connect },
                    unsafe { value.common_data.network.family },
                );
                let data = NetworkData::Connect(data);
                EventData::Network {
                    process,
                    network: data,
                }
            }
            _ => unreachable!(),
        };

        Ok(data)
    }
}

impl TryFrom<process_t> for EventData {
    type Error = anyhow::Error;

    fn try_from(value: process_t) -> Result<Self, Self::Error> {
        let proc = Process::try_from(value)?;
        Ok(EventData::Process(ProcessData::Proc(proc)))
    }
}

impl From<EventData> for fact_api::fact_msg::Msg {
    fn from(value: EventData) -> Self {
        match value {
            EventData::File { file, process } => {
                let activity = fact_api::FileActivity {
                    file: Some(file.into()),
                    process: Some(process.into()),
                };
                fact_api::fact_msg::Msg::File(activity)
            }
            EventData::Process(data) => {
                let activity = fact_api::ProcessActivity {
                    process: Some(data.into()),
                };
                fact_api::fact_msg::Msg::Process(activity)
            }
            EventData::Network {
                process,
                network: socket,
            } => {
                let activity = fact_api::NetworkActivity {
                    process: Some(process.into()),
                    net: Some(socket.into()),
                };
                fact_api::fact_msg::Msg::Net(activity)
            }
        }
    }
}

impl From<fact_api::fact_msg::Msg> for EventData {
    fn from(value: fact_api::fact_msg::Msg) -> Self {
        match value {
            fact_api::fact_msg::Msg::File(fact_api::FileActivity {
                process: Some(proc),
                file: Some(file),
            }) => EventData::File {
                process: proc.into(),
                file: file.into(),
            },
            fact_api::fact_msg::Msg::Process(fact_api::ProcessActivity {
                process: Some(proc),
            }) => EventData::Process(proc.into()),
            fact_api::fact_msg::Msg::Net(fact_api::NetworkActivity {
                process: Some(proc),
                net: Some(net),
            }) => EventData::Network {
                process: proc.into(),
                network: net.into(),
            },
            _ => unreachable!("Invalid protobuf received"),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum FileData {
    Open(BaseFileData),
    Creation(BaseFileData),
    Unlink(BaseFileData),
    Chmod(ChmodFileData),
    Chown(ChownFileData),
    Rename(RenameFileData),
}

impl FileData {
    pub fn new(
        event_type: fact_event_type_t,
        filename: [c_char; PATH_MAX as usize],
        inode: inode_key_t,
        extra_data: fact_ebpf::event_t__bindgen_ty_2,
    ) -> anyhow::Result<Self> {
        let inner = BaseFileData::new(filename, inode)?;
        let file = match event_type {
            fact_event_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            fact_event_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            fact_event_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            fact_event_type_t::FILE_ACTIVITY_CHMOD => {
                let data = ChmodFileData {
                    inner,
                    new_mode: unsafe { extra_data.chmod.new },
                    old_mode: unsafe { extra_data.chmod.old },
                };
                FileData::Chmod(data)
            }
            fact_event_type_t::FILE_ACTIVITY_CHOWN => {
                let data = ChownFileData {
                    inner,
                    new_uid: unsafe { extra_data.chown.new.uid },
                    new_gid: unsafe { extra_data.chown.new.gid },
                    old_uid: unsafe { extra_data.chown.old.uid },
                    old_gid: unsafe { extra_data.chown.old.gid },
                };
                FileData::Chown(data)
            }
            fact_event_type_t::FILE_ACTIVITY_RENAME => {
                let old_filename = unsafe { extra_data.rename.old_filename };
                let old_inode = unsafe { extra_data.rename.old_inode };
                let data = RenameFileData {
                    new: inner,
                    old: BaseFileData::new(old_filename, old_inode)?,
                };
                FileData::Rename(data)
            }
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(file)
    }
}

impl From<FileData> for fact_api::file_activity::File {
    fn from(event: FileData) -> Self {
        match event {
            FileData::Open(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileOpen { activity };
                fact_api::file_activity::File::Open(f_act)
            }
            FileData::Creation(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileCreation { activity };
                fact_api::file_activity::File::Creation(f_act)
            }
            FileData::Unlink(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileUnlink { activity };
                fact_api::file_activity::File::Unlink(f_act)
            }
            FileData::Chmod(event) => {
                let f_act = fact_api::FilePermissionChange::from(event);
                fact_api::file_activity::File::Permission(f_act)
            }
            FileData::Chown(event) => {
                let f_act = fact_api::FileOwnershipChange::from(event);
                fact_api::file_activity::File::Ownership(f_act)
            }
            FileData::Rename(event) => {
                let f_act = fact_api::FileRename::from(event);
                fact_api::file_activity::File::Rename(f_act)
            }
        }
    }
}

impl From<fact_api::file_activity::File> for FileData {
    fn from(value: fact_api::file_activity::File) -> Self {
        match value {
            fact_api::file_activity::File::Creation(fact_api::FileCreation {
                activity: Some(data),
            }) => FileData::Creation(data.into()),
            fact_api::file_activity::File::Open(fact_api::FileOpen {
                activity: Some(data),
            }) => FileData::Open(data.into()),
            fact_api::file_activity::File::Unlink(fact_api::FileUnlink {
                activity: Some(data),
            }) => FileData::Unlink(data.into()),
            fact_api::file_activity::File::Permission(fact_api::FilePermissionChange {
                activity: Some(data),
                mode,
            }) => FileData::Chmod(ChmodFileData {
                inner: data.into(),
                new_mode: mode as u16,
                old_mode: 0,
            }),
            fact_api::file_activity::File::Ownership(fact_api::FileOwnershipChange {
                activity: Some(data),
                uid,
                gid,
                ..
            }) => FileData::Chown(ChownFileData {
                inner: data.into(),
                new_uid: uid,
                new_gid: gid,
                old_uid: 0,
                old_gid: 0,
            }),
            fact_api::file_activity::File::Rename(fact_api::FileRename {
                old: Some(old),
                new: Some(new),
            }) => FileData::Rename(RenameFileData {
                new: new.into(),
                old: old.into(),
            }),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BaseFileData {
    pub filename: PathBuf,
    host_file: PathBuf,
    inode: inode_key_t,
}

impl BaseFileData {
    pub fn new(filename: [c_char; PATH_MAX as usize], inode: inode_key_t) -> anyhow::Result<Self> {
        Ok(BaseFileData {
            filename: sanitize_d_path(&filename),
            host_file: PathBuf::new(), // this field is set by HostScanner
            inode,
        })
    }
}

impl PartialEq for BaseFileData {
    fn eq(&self, other: &Self) -> bool {
        self.filename == other.filename && self.host_file == other.host_file
    }
}

impl From<BaseFileData> for fact_api::FileActivityBase {
    fn from(value: BaseFileData) -> Self {
        fact_api::FileActivityBase {
            path: value.filename.to_string_lossy().to_string(),
            host_path: value.host_file.to_string_lossy().to_string(),
        }
    }
}

impl From<fact_api::FileActivityBase> for BaseFileData {
    fn from(fact_api::FileActivityBase { path, host_path }: fact_api::FileActivityBase) -> Self {
        BaseFileData {
            filename: path.into(),
            host_file: host_path.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChmodFileData {
    inner: BaseFileData,
    new_mode: u16,
    old_mode: u16,
}

impl From<ChmodFileData> for fact_api::FilePermissionChange {
    fn from(value: ChmodFileData) -> Self {
        let ChmodFileData {
            inner: file,
            new_mode,
            ..
        } = value;
        let activity = fact_api::FileActivityBase::from(file);
        fact_api::FilePermissionChange {
            activity: Some(activity),
            mode: new_mode as u32,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChownFileData {
    inner: BaseFileData,
    new_uid: u32,
    new_gid: u32,
    old_uid: u32,
    old_gid: u32,
}

impl From<ChownFileData> for fact_api::FileOwnershipChange {
    fn from(value: ChownFileData) -> Self {
        let ChownFileData {
            inner: file,
            new_uid,
            new_gid,
            ..
        } = value;
        let activity = fact_api::FileActivityBase::from(file);
        fact_api::FileOwnershipChange {
            activity: Some(activity),
            uid: new_uid,
            gid: new_gid,
            username: "".to_string(),
            group: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RenameFileData {
    new: BaseFileData,
    old: BaseFileData,
}

impl From<RenameFileData> for fact_api::FileRename {
    fn from(RenameFileData { new, old }: RenameFileData) -> Self {
        let new = fact_api::FileActivityBase::from(new);
        let old = fact_api::FileActivityBase::from(old);
        fact_api::FileRename {
            old: Some(old),
            new: Some(new),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ProcessData {
    Fork(ProcessForkData),
    Exec(ProcessExecData),
    Exit(ProcessExitData),
    Proc(Process),
}

impl From<ProcessData> for fact_api::process_activity::Process {
    fn from(value: ProcessData) -> Self {
        match value {
            ProcessData::Fork(data) => fact_api::process_activity::Process::Fork(data.into()),
            ProcessData::Exec(proc) => fact_api::process_activity::Process::Exec(proc.into()),
            ProcessData::Exit(proc) => fact_api::process_activity::Process::Exit(proc.into()),
            ProcessData::Proc(proc) => fact_api::process_activity::Process::Proc(proc.into()),
        }
    }
}

impl From<fact_api::process_activity::Process> for ProcessData {
    fn from(value: fact_api::process_activity::Process) -> Self {
        match value {
            fact_api::process_activity::Process::Fork(data) => ProcessData::Fork(data.into()),
            fact_api::process_activity::Process::Exec(process) => ProcessData::Exec(process.into()),
            fact_api::process_activity::Process::Proc(process) => ProcessData::Proc(process.into()),
            fact_api::process_activity::Process::Exit(process) => ProcessData::Exit(process.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProcessForkData {
    pub child: Process,
}

impl From<ProcessForkData> for fact_api::ProcessFork {
    fn from(ProcessForkData { child }: ProcessForkData) -> Self {
        fact_api::ProcessFork {
            child: Some(child.into()),
        }
    }
}

impl From<fact_api::ProcessFork> for ProcessForkData {
    fn from(value: fact_api::ProcessFork) -> Self {
        match value {
            fact_api::ProcessFork { child: Some(child) } => ProcessForkData {
                child: child.into(),
            },
            _ => unreachable!("Invalid process fork message received"),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProcessExecData(pub Process);

impl From<ProcessExecData> for fact_api::Process {
    fn from(ProcessExecData(proc): ProcessExecData) -> Self {
        proc.into()
    }
}

impl From<fact_api::Process> for ProcessExecData {
    fn from(proc: fact_api::Process) -> Self {
        ProcessExecData(proc.into())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProcessExitData(pub Process);

impl From<ProcessExitData> for fact_api::Process {
    fn from(ProcessExitData(proc): ProcessExitData) -> Self {
        proc.into()
    }
}

impl From<fact_api::Process> for ProcessExitData {
    fn from(proc: fact_api::Process) -> Self {
        ProcessExitData(proc.into())
    }
}

#[cfg(test)]
mod test_utils {
    use std::os::raw::c_char;

    /// Helper function to convert raw bytes to a c_char array for testing
    pub fn bytes_to_c_char_array<const N: usize>(bytes: &[u8]) -> [c_char; N] {
        let mut array = [0 as c_char; N];
        let len = bytes.len().min(N - 1);
        for (i, &byte) in bytes.iter().take(len).enumerate() {
            array[i] = byte as c_char;
        }
        array
    }

    /// Helper function to convert a Rust string to a c_char array for testing
    pub fn string_to_c_char_array<const N: usize>(s: &str) -> [c_char; N] {
        bytes_to_c_char_array(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;

    #[test]
    fn slice_to_string_valid_utf8() {
        let tests = [
            ("hello", "ASCII"),
            ("café", "French"),
            ("файл", "Cyrillic"),
            ("测试文件", "Chinese"),
            ("test🚀file", "Emoji"),
            ("test-файл-测试-🐛.txt", "Mixed Unicode"),
            ("ملف", "Arabic"),
            ("קובץ", "Hebrew"),
            ("ファイル", "Japanese"),
        ];

        for (input, description) in tests {
            let arr = string_to_c_char_array::<{ PATH_MAX as usize }>(input);
            assert_eq!(
                slice_to_string(&arr).unwrap(),
                input,
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn slice_to_string_invalid_utf8() {
        let tests: &[(&[u8], &str)] = &[
            (&[0xFF, 0xFE, 0xFD], "Invalid continuation bytes"),
            (b"test\xE2", "Truncated multi-byte sequence"),
            (&[0xC0, 0x80], "Overlong encoding"),
            (b"hello\x80world", "Invalid start byte"),
            (&[0x80], "Lone continuation byte"),
            (b"test\xFF\xFE", "Mixed valid and invalid bytes"),
        ];

        for (bytes, description) in tests {
            let arr = bytes_to_c_char_array::<{ PATH_MAX as usize }>(bytes);
            assert!(
                slice_to_string(&arr).is_err(),
                "Should fail for {}",
                description
            );
        }
    }

    #[test]
    fn sanitize_d_path_valid_utf8() {
        let tests = [
            ("/etc/test", "/etc/test", "ASCII"),
            ("/tmp/файл.txt", "/tmp/файл.txt", "Cyrillic"),
            (
                "/home/user/测试文件.log",
                "/home/user/测试文件.log",
                "Chinese",
            ),
            ("/data/🚀rocket.dat", "/data/🚀rocket.dat", "Emoji"),
            (
                "/var/log/app-данные-数据-🐛.log",
                "/var/log/app-данные-数据-🐛.log",
                "Mixed Unicode",
            ),
            ("/home/ملف.txt", "/home/ملف.txt", "Arabic"),
            ("/opt/ファイル.conf", "/opt/ファイル.conf", "Japanese"),
        ];

        for (input, expected, description) in tests {
            let arr = string_to_c_char_array::<{ PATH_MAX as usize }>(input);
            assert_eq!(
                sanitize_d_path(&arr),
                PathBuf::from(expected),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn sanitize_d_path_deleted_suffix() {
        let tests = [
            (
                "/tmp/test.txt (deleted)",
                "/tmp/test.txt",
                "ASCII with deleted suffix",
            ),
            (
                "/tmp/файл.txt (deleted)",
                "/tmp/файл.txt",
                "Unicode with deleted suffix",
            ),
            ("/etc/config.yaml", "/etc/config.yaml", "No deleted suffix"),
            (
                "/var/log/app/debug.log (deleted)",
                "/var/log/app/debug.log",
                "Nested path with deleted suffix",
            ),
        ];

        for (input, expected, description) in tests {
            let arr = string_to_c_char_array::<{ PATH_MAX as usize }>(input);
            assert_eq!(
                sanitize_d_path(&arr),
                PathBuf::from(expected),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8() {
        use regex::Regex;

        let tests: &[(&[u8], &str, &str)] = &[
            (
                b"/tmp/\xFF\xFE.txt",
                r"^/tmp/\u{FFFD}+\.txt$",
                "Invalid continuation bytes",
            ),
            (
                b"/var/test\xE2\x80",
                r"^/var/test\u{FFFD}+$",
                "Truncated multi-byte sequence",
            ),
            (
                b"/home/file\x80.log",
                r"^/home/file\u{FFFD}\.log$",
                "Invalid start byte",
            ),
            (
                b"/tmp/\xD1\x84\xFF\xD0\xBB.txt",
                r"^/tmp/ф\u{FFFD}л\.txt$",
                "Mixed valid and invalid UTF-8",
            ),
        ];

        for (bytes, pattern, description) in tests {
            let arr = bytes_to_c_char_array::<{ PATH_MAX as usize }>(bytes);
            let result = sanitize_d_path(&arr);
            let result_str = result.to_string_lossy();

            let re = Regex::new(pattern).expect("Invalid regex pattern");
            assert!(
                re.is_match(&result_str),
                "Failed for {}: expected pattern '{}', got '{}'",
                description,
                pattern,
                result_str
            );
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8_with_deleted_suffix() {
        let invalid_with_deleted =
            bytes_to_c_char_array::<{ PATH_MAX as usize }>(b"/tmp/\xFF\xFE (deleted)");
        let result = sanitize_d_path(&invalid_with_deleted);
        let result_str = result.to_string_lossy();

        assert!(result_str.contains("/tmp/"));
        assert!(!result_str.ends_with(" (deleted)"));
        assert!(result_str.contains('\u{FFFD}'));
    }
}
