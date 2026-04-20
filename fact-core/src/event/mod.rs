#[cfg(feature = "otel")]
use std::collections::HashMap;
use std::{
    ffi::{CStr, OsStr},
    os::{raw::c_char, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
};

use globset::GlobSet;
use libc::CLOCK_REALTIME;
#[cfg(feature = "otel")]
use opentelemetry::logs::AnyValue;
use serde::{Deserialize, Serialize};

use fact_ebpf::{
    PATH_MAX, XATTR_NAME_MAX_LEN, event_t, fact_event_type_t, inode_key_t, monitored_t, process_t,
};

use crate::{
    event::network::{AcceptData, ListenData, NetworkData},
    host_info,
};
use process::Process;

pub mod network;
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

#[cfg(all(test, feature = "bpf-test"))]
#[derive(Debug)]
pub enum EventTestData {
    Creation,
    Unlink,
    Chmod(u16, u16),
    Rename(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    timestamp: u64,
    hostname: String,
    pub data: EventData,
}

impl Event {
    #[cfg(all(test, feature = "bpf-test"))]
    pub(crate) fn new(
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
            parent_inode: Default::default(),
            monitored: Default::default(),
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
            EventTestData::Rename(old_path) => FileData::Rename {
                new: inner,
                old: BaseFileData {
                    filename: old_path,
                    ..Default::default()
                },
            },
        };

        let data = EventData::File { process, file };

        Ok(Event {
            timestamp,
            hostname: hostname.to_string(),
            data,
        })
    }

    pub fn is_creation(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Creation(_) | FileData::MkDir(_) | FileData::Symlink { .. },
                ..
            }
        )
    }

    pub fn is_xattr(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::SetXattr(_) | FileData::RemoveXattr(_),
                ..
            }
        )
    }

    pub fn is_mkdir(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::MkDir(_),
                ..
            }
        )
    }

    pub fn is_rmdir(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::RmDir(_),
                ..
            }
        )
    }

    pub fn is_deletion(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Unlink(_) | FileData::RmDir(_),
                ..
            }
        )
    }

    pub fn is_link(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Link(_),
                ..
            }
        )
    }

    pub fn is_rename(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Rename { .. },
                ..
            }
        )
    }

    pub fn is_mount_related(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Mount(_) | FileData::Umount(_) | FileData::MoveMount { .. },
                ..
            }
        )
    }

    pub fn is_symlink(&self) -> bool {
        matches!(
            self.data,
            EventData::File {
                file: FileData::Symlink { .. },
                ..
            }
        )
    }

    /// Unwrap the inner FileData and return the inode that triggered
    /// the event.
    ///
    /// In the case of operations that involve two inodes, like rename,
    /// the 'new' inode will be returned.
    pub fn get_inode(&self) -> Option<&inode_key_t> {
        match &self.data {
            EventData::File { file, .. } => match file {
                FileData::Open(inner)
                | FileData::Creation(inner)
                | FileData::MkDir(inner)
                | FileData::RmDir(inner)
                | FileData::Link(inner)
                | FileData::Unlink(inner)
                | FileData::Chmod(ChmodFileData { inner, .. })
                | FileData::Chown(ChownFileData { inner, .. })
                | FileData::Rename { new: inner, .. }
                | FileData::MoveMount { to: inner, .. }
                | FileData::Mount(inner)
                | FileData::Umount(inner)
                | FileData::Symlink { inner, .. }
                | FileData::SetXattr(XattrFileData { inner, .. })
                | FileData::RemoveXattr(XattrFileData { inner, .. })
                | FileData::AclSet(AclSetFileData { inner, .. }) => Some(&inner.inode),
            },
            _ => None,
        }
    }

    /// Get the parent inode for the file in this event.
    pub fn get_parent_inode(&self) -> Option<&inode_key_t> {
        match &self.data {
            EventData::File { file, .. } => match file {
                FileData::Open(inner)
                | FileData::Creation(inner)
                | FileData::MkDir(inner)
                | FileData::RmDir(inner)
                | FileData::Link(inner)
                | FileData::Unlink(inner)
                | FileData::Chmod(ChmodFileData { inner, .. })
                | FileData::Chown(ChownFileData { inner, .. })
                | FileData::Rename { new: inner, .. }
                | FileData::MoveMount { to: inner, .. }
                | FileData::Mount(inner)
                | FileData::Umount(inner)
                | FileData::Symlink { inner, .. }
                | FileData::SetXattr(XattrFileData { inner, .. })
                | FileData::RemoveXattr(XattrFileData { inner, .. })
                | FileData::AclSet(AclSetFileData { inner, .. }) => Some(&inner.parent_inode),
            },
            _ => None,
        }
    }

    /// Same as `get_inode` but returning the 'old' inode for operations
    /// like rename. For operations that involve a single inode, `None`
    /// will be returned.
    pub fn get_old_inode(&self) -> Option<&inode_key_t> {
        match &self.data {
            EventData::File {
                file: FileData::Rename { old: from, .. } | FileData::MoveMount { from, .. },
                ..
            } => Some(&from.inode),
            _ => None,
        }
    }

    pub fn get_filename(&self) -> Option<&PathBuf> {
        match &self.data {
            EventData::File { file, .. } => Some(file.get_filename()),
            _ => None,
        }
    }

    pub fn get_old_filename(&self) -> Option<&PathBuf> {
        match &self.data {
            EventData::File {
                file: FileData::Rename { old: from, .. } | FileData::MoveMount { from, .. },
                ..
            } => Some(&from.filename),
            _ => None,
        }
    }

    pub fn get_host_path(&self) -> Option<&PathBuf> {
        match &self.data {
            EventData::File { file, .. } => Some(file.get_host_path()),
            _ => None,
        }
    }

    pub fn get_old_host_path(&self) -> Option<&PathBuf> {
        match &self.data {
            EventData::File {
                file: FileData::Rename { old: from, .. } | FileData::MoveMount { from, .. },
                ..
            } => Some(&from.host_file),
            _ => None,
        }
    }

    /// Set the `host_file` field of the event to the one provided.
    ///
    /// In the case of operations that involve two paths, like rename,
    /// the 'new' host_file will be set.
    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.data {
            EventData::File { file, .. } => match file {
                FileData::Open(inner)
                | FileData::Creation(inner)
                | FileData::MkDir(inner)
                | FileData::RmDir(inner)
                | FileData::Link(inner)
                | FileData::Unlink(inner)
                | FileData::Chmod(ChmodFileData { inner, .. })
                | FileData::Chown(ChownFileData { inner, .. })
                | FileData::Rename { new: inner, .. }
                | FileData::MoveMount { to: inner, .. }
                | FileData::Mount(inner)
                | FileData::Umount(inner)
                | FileData::Symlink { inner, .. }
                | FileData::SetXattr(XattrFileData { inner, .. })
                | FileData::RemoveXattr(XattrFileData { inner, .. })
                | FileData::AclSet(AclSetFileData { inner, .. }) => inner.host_file = host_path,
            },
            _ => {}
        }
    }

    /// Same as `set_host_path` but setting the 'old' host_file for
    /// operations that have one, like rename.
    pub fn set_old_host_path(&mut self, host_path: PathBuf) {
        match &mut self.data {
            EventData::File {
                file: FileData::Rename { old: from, .. } | FileData::MoveMount { from, .. },
                ..
            } => from.host_file = host_path,
            _ => unreachable!("Called set_old_host_path on invalid type"),
        }
    }

    pub fn get_monitored(&self) -> Option<monitored_t> {
        match &self.data {
            EventData::File {
                file:
                    FileData::Open(inner)
                    | FileData::Creation(inner)
                    | FileData::MkDir(inner)
                    | FileData::RmDir(inner)
                    | FileData::Link(inner)
                    | FileData::Unlink(inner)
                    | FileData::Chmod(ChmodFileData { inner, .. })
                    | FileData::Chown(ChownFileData { inner, .. })
                    | FileData::Rename { new: inner, .. }
                    | FileData::MoveMount { to: inner, .. }
                    | FileData::Mount(inner)
                    | FileData::Umount(inner)
                    | FileData::Symlink { inner, .. }
                    | FileData::SetXattr(XattrFileData { inner, .. })
                    | FileData::RemoveXattr(XattrFileData { inner, .. })
                    | FileData::AclSet(AclSetFileData { inner, .. }),
                ..
            } => Some(inner.monitored),
            _ => None,
        }
    }

    pub fn get_old_monitored(&self) -> Option<monitored_t> {
        match &self.data {
            EventData::File {
                file: FileData::Rename { old: from, .. } | FileData::MoveMount { from, .. },
                ..
            } => Some(from.monitored),
            _ => None,
        }
    }

    /// Determine if the event should be ignored.
    ///
    /// With wildcards, the kernel can only match on the inode and
    /// then the longest non-wildcard prefix (e.g. for /etc/**/*.conf,
    /// the kernel matches up to /etc/).
    ///
    /// The kernel sets inode to 0 when it matched via path prefix only.
    /// so we only need to perform a glob match against the filename.
    ///
    /// We also need to check the old values for rename events.
    pub fn is_ignored(&self, globset: &GlobSet) -> bool {
        if !matches!(self.data, EventData::File { .. }) {
            return false;
        }

        self.get_monitored() != Some(monitored_t::MONITORED_BY_INODE)
            && self
                .get_old_monitored()
                .is_none_or(|m| m != monitored_t::MONITORED_BY_INODE)
            && self
                .get_filename()
                .is_none_or(|path| !globset.is_match(path))
            && self
                .get_old_filename()
                .is_none_or(|path| !globset.is_match(path))
    }

    pub fn is_monitored_by_parent(&self) -> bool {
        self.get_monitored() == Some(monitored_t::MONITORED_BY_PARENT)
    }

    #[cfg(feature = "otel")]
    pub fn event_type(&self) -> &'static str {
        use EventData::*;
        match &self.data {
            File { file, .. } => file.event_type(),
            Process(proc) => proc.event_type(),
            Network { network, .. } => network.event_type(),
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

#[cfg(feature = "otel")]
impl From<Event> for opentelemetry::logs::AnyValue {
    fn from(value: Event) -> Self {
        let mut map = HashMap::from([
            ("timestamp".into(), AnyValue::Int(value.timestamp as i64)),
            ("hostname".into(), value.hostname.into()),
        ]);

        match value.data {
            EventData::File { process, file } => {
                map.insert("file".into(), file.into());
                map.insert("process".into(), process.into());
            }
            EventData::Process(
                ProcessData::Fork(ProcessForkData { child: proc })
                | ProcessData::Proc(proc)
                | ProcessData::Exec(ProcessExecData(proc))
                | ProcessData::Exit(ProcessExitData(proc)),
            ) => {
                map.insert("process".into(), proc.into());
            }
            EventData::Network { process, network } => {
                map.insert("network".into(), network.into());
                map.insert("process".into(), process.into());
            }
        }

        AnyValue::Map(Box::new(map))
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.data == other.data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
            | fact_event_type_t::FILE_ACTIVITY_LINK
            | fact_event_type_t::FILE_ACTIVITY_UNLINK
            | fact_event_type_t::FILE_ACTIVITY_CHMOD
            | fact_event_type_t::FILE_ACTIVITY_CHOWN
            | fact_event_type_t::FILE_ACTIVITY_RENAME
            | fact_event_type_t::DIR_ACTIVITY_CREATION
            | fact_event_type_t::DIR_ACTIVITY_UNLINK
            | fact_event_type_t::FILE_ACTIVITY_SETXATTR
            | fact_event_type_t::FILE_ACTIVITY_REMOVEXATTR
            | fact_event_type_t::FILE_ACTIVITY_ACL_SET
            | fact_event_type_t::FILE_ACTIVITY_MOUNT
            | fact_event_type_t::FILE_ACTIVITY_UMOUNT
            | fact_event_type_t::FILE_ACTIVITY_MOVE_MOUNT
            | fact_event_type_t::FILE_ACTIVITY_SYMLINK => EventData::File {
                file: FileData::new(
                    value.type_,
                    unsafe { value.common_data.file.path },
                    unsafe { value.common_data.file.inode },
                    unsafe { value.common_data.file.parent_inode },
                    unsafe { value.common_data.file.monitored },
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
                let socket = ListenData::new(unsafe { value.common_data.network });
                let socket = NetworkData::Listen(socket);
                EventData::Network {
                    process,
                    network: socket,
                }
            }
            fact_event_type_t::SOCKET_ACCEPT => {
                let data = AcceptData::new(unsafe { value.common_data.network });
                let data = NetworkData::Accept(data);
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileData {
    Open(BaseFileData),
    Creation(BaseFileData),
    MkDir(BaseFileData),
    RmDir(BaseFileData),
    Link(BaseFileData),
    Unlink(BaseFileData),
    Chmod(ChmodFileData),
    Chown(ChownFileData),
    Rename {
        new: BaseFileData,
        old: BaseFileData,
    },
    SetXattr(XattrFileData),
    RemoveXattr(XattrFileData),
    AclSet(AclSetFileData),
    Mount(BaseFileData),
    MoveMount {
        to: BaseFileData,
        from: BaseFileData,
    },
    Umount(BaseFileData),
    Symlink {
        inner: BaseFileData,
        target: PathBuf,
    },
}

impl FileData {
    pub fn new(
        event_type: fact_event_type_t,
        filename: [c_char; PATH_MAX as usize],
        inode: inode_key_t,
        parent_inode: inode_key_t,
        monitored: monitored_t,
        extra_data: fact_ebpf::event_t__bindgen_ty_2,
    ) -> anyhow::Result<Self> {
        fn read_from_data(extra_data: fact_ebpf::event_t__bindgen_ty_2) -> BaseFileData {
            let filename = unsafe { extra_data.from.filename };
            let inode = unsafe { extra_data.from.inode };
            let monitored = unsafe { extra_data.from.monitored };

            BaseFileData::new(filename, inode, Default::default(), monitored)
        }

        let inner = BaseFileData::new(filename, inode, parent_inode, monitored);
        let file = match event_type {
            fact_event_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            fact_event_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            fact_event_type_t::DIR_ACTIVITY_CREATION => FileData::MkDir(inner),
            fact_event_type_t::DIR_ACTIVITY_UNLINK => FileData::RmDir(inner),
            fact_event_type_t::FILE_ACTIVITY_LINK => FileData::Link(inner),
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
                let old = read_from_data(extra_data);
                FileData::Rename { new: inner, old }
            }
            fact_event_type_t::FILE_ACTIVITY_SETXATTR => {
                let xattr_name = slice_to_string(
                    &unsafe { extra_data.xattr }.name[..XATTR_NAME_MAX_LEN as usize],
                )?;
                FileData::SetXattr(XattrFileData { inner, xattr_name })
            }
            fact_event_type_t::FILE_ACTIVITY_REMOVEXATTR => {
                let xattr_name = slice_to_string(
                    &unsafe { extra_data.xattr }.name[..XATTR_NAME_MAX_LEN as usize],
                )?;
                FileData::RemoveXattr(XattrFileData { inner, xattr_name })
            }
            fact_event_type_t::FILE_ACTIVITY_ACL_SET => {
                let acl = unsafe { &extra_data.acl };
                let acl_type = if acl.acl_type == fact_ebpf::acl_type_t::FACT_ACL_TYPE_DEFAULT {
                    AclType::Default
                } else {
                    AclType::Access
                };
                let count = acl.count.min(fact_ebpf::FACT_MAX_ACL_ENTRIES) as usize;
                let entries = acl.entries[0..count].iter().map(AclEntry::new).collect();
                FileData::AclSet(AclSetFileData {
                    inner,
                    acl_type,
                    entries,
                })
            }
            fact_event_type_t::FILE_ACTIVITY_MOUNT => FileData::Mount(inner),
            fact_event_type_t::FILE_ACTIVITY_UMOUNT => FileData::Umount(inner),
            fact_event_type_t::FILE_ACTIVITY_MOVE_MOUNT => {
                let from = read_from_data(extra_data);
                FileData::MoveMount { to: inner, from }
            }
            fact_event_type_t::FILE_ACTIVITY_SYMLINK => {
                let target = unsafe { extra_data.from.filename };
                let target = sanitize_d_path(&target);
                FileData::Symlink { inner, target }
            }
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(file)
    }

    #[cfg(feature = "otel")]
    fn event_type(&self) -> &'static str {
        match self {
            FileData::Open(_) => "open",
            FileData::Creation(_) => "creation",
            FileData::MkDir(_) => "mkdir",
            FileData::RmDir(_) => "rmdir",
            FileData::Link(_) => "link",
            FileData::Unlink(_) => "unlink",
            FileData::Chmod(_) => "permission",
            FileData::Chown(_) => "ownership",
            FileData::Rename { .. } => "rename",
            FileData::SetXattr(_) => "xattr_set",
            FileData::RemoveXattr(_) => "xattr_remove",
            FileData::AclSet(_) => "acl",
            FileData::Mount(_) => "mount",
            FileData::MoveMount { .. } => "move_mount",
            FileData::Umount(_) => "umount",
            FileData::Symlink { .. } => "symlink",
        }
    }

    pub fn get_filename(&self) -> &PathBuf {
        match self {
            FileData::Open(inner)
            | FileData::Creation(inner)
            | FileData::MkDir(inner)
            | FileData::RmDir(inner)
            | FileData::Link(inner)
            | FileData::Unlink(inner)
            | FileData::Chmod(ChmodFileData { inner, .. })
            | FileData::Chown(ChownFileData { inner, .. })
            | FileData::Rename { new: inner, .. }
            | FileData::MoveMount { to: inner, .. }
            | FileData::Mount(inner)
            | FileData::Umount(inner)
            | FileData::Symlink { inner, .. }
            | FileData::SetXattr(XattrFileData { inner, .. })
            | FileData::RemoveXattr(XattrFileData { inner, .. })
            | FileData::AclSet(AclSetFileData { inner, .. }) => &inner.filename,
        }
    }

    pub fn get_host_path(&self) -> &PathBuf {
        match self {
            FileData::Open(inner)
            | FileData::Creation(inner)
            | FileData::MkDir(inner)
            | FileData::RmDir(inner)
            | FileData::Link(inner)
            | FileData::Unlink(inner)
            | FileData::Chmod(ChmodFileData { inner, .. })
            | FileData::Chown(ChownFileData { inner, .. })
            | FileData::Rename { new: inner, .. }
            | FileData::MoveMount { to: inner, .. }
            | FileData::Mount(inner)
            | FileData::Umount(inner)
            | FileData::Symlink { inner, .. }
            | FileData::SetXattr(XattrFileData { inner, .. })
            | FileData::RemoveXattr(XattrFileData { inner, .. })
            | FileData::AclSet(AclSetFileData { inner, .. }) => &inner.host_file,
        }
    }
}

impl From<FileData> for fact_api::file_activity::File {
    fn from(event: FileData) -> Self {
        match event {
            FileData::Open(event) | FileData::Symlink { inner: event, .. } => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileOpen { activity };
                fact_api::file_activity::File::Open(f_act)
            }
            FileData::Creation(event) | FileData::Link(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileCreation { activity };
                fact_api::file_activity::File::Creation(f_act)
            }
            FileData::MkDir(_) => {
                unreachable!("MkDir event reached protobuf conversion");
            }
            FileData::RmDir(_) => {
                unreachable!("RmDir event reached protobuf conversion");
            }
            FileData::SetXattr(event) => {
                let f_act = fact_api::FileXattrChange::from(event);
                fact_api::file_activity::File::XattrSet(f_act)
            }
            FileData::RemoveXattr(event) => {
                let f_act = fact_api::FileXattrChange::from(event);
                fact_api::file_activity::File::XattrRemove(f_act)
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
            FileData::Rename { new, old } => {
                let f_act = fact_api::FileRename {
                    new: Some(new.into()),
                    old: Some(old.into()),
                };
                fact_api::file_activity::File::Rename(f_act)
            }
            FileData::AclSet(event) => {
                let f_act = fact_api::FileAclChange::from(event);
                fact_api::file_activity::File::Acl(f_act)
            }
            FileData::Mount(_) => {
                unreachable!("Mount event reached protobuf conversion");
            }
            FileData::MoveMount { .. } => {
                unreachable!("MoveMount event reached protobuf conversion");
            }
            FileData::Umount(_) => {
                unreachable!("Umount event reached protobuf conversion");
            }
        }
    }
}

#[cfg(feature = "otel")]
impl From<FileData> for opentelemetry::logs::AnyValue {
    fn from(value: FileData) -> Self {
        let event_type = value.event_type();
        let AnyValue::Map(mut map) = (match value {
            FileData::Open(data)
            | FileData::Creation(data)
            | FileData::MkDir(data)
            | FileData::RmDir(data)
            | FileData::Mount(data)
            | FileData::Umount(data)
            | FileData::Link(data)
            | FileData::Unlink(data) => AnyValue::from(data),
            FileData::Chmod(data) => AnyValue::from(data),
            FileData::Chown(data) => AnyValue::from(data),
            FileData::MoveMount { to, from } | FileData::Rename { new: to, old: from } => {
                let AnyValue::Map(mut map) = AnyValue::from(to) else {
                    unreachable!("to value did not serialize to map");
                };
                map.insert("old".into(), AnyValue::from(from));

                AnyValue::Map(map)
            }
            FileData::SetXattr(data) | FileData::RemoveXattr(data) => AnyValue::from(data),
            FileData::AclSet(data) => AnyValue::from(data),
            FileData::Symlink { inner, target } => {
                let AnyValue::Map(mut map) = AnyValue::from(inner) else {
                    unreachable!("to value did not serialize to map");
                };
                map.insert("target".into(), target.to_string_lossy().to_string().into());

                AnyValue::Map(map)
            }
        }) else {
            unreachable!("event data did not serialize to map");
        };

        map.insert("event_type".into(), event_type.into());

        AnyValue::Map(map)
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
            }) => FileData::Rename {
                new: new.into(),
                old: old.into(),
            },
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BaseFileData {
    pub filename: PathBuf,
    host_file: PathBuf,
    inode: inode_key_t,
    parent_inode: inode_key_t,
    monitored: monitored_t,
}

impl BaseFileData {
    pub fn new(
        filename: [c_char; PATH_MAX as usize],
        inode: inode_key_t,
        parent_inode: inode_key_t,
        monitored: monitored_t,
    ) -> Self {
        BaseFileData {
            filename: sanitize_d_path(&filename),
            host_file: PathBuf::new(), // this field is set by HostScanner
            inode,
            parent_inode,
            monitored,
        }
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

#[cfg(feature = "otel")]
impl From<BaseFileData> for opentelemetry::logs::AnyValue {
    fn from(value: BaseFileData) -> Self {
        AnyValue::Map(Box::new(HashMap::from([
            (
                "filename".into(),
                value.filename.to_string_lossy().to_string().into(),
            ),
            (
                "host_path".into(),
                value.host_file.to_string_lossy().to_string().into(),
            ),
        ])))
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[cfg(feature = "otel")]
impl From<ChmodFileData> for opentelemetry::logs::AnyValue {
    fn from(value: ChmodFileData) -> Self {
        let AnyValue::Map(mut map) = value.inner.into() else {
            unreachable!("inner value did not serialize to map");
        };
        map.extend([
            ("new_mode".into(), value.new_mode.into()),
            ("old_mode".into(), value.old_mode.into()),
        ]);

        AnyValue::Map(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[cfg(feature = "otel")]
impl From<ChownFileData> for opentelemetry::logs::AnyValue {
    fn from(value: ChownFileData) -> Self {
        let AnyValue::Map(mut map) = value.inner.into() else {
            unreachable!("inner value did not serialize to map");
        };
        map.extend([
            ("new_uid".into(), value.new_uid.into()),
            ("old_uid".into(), value.old_uid.into()),
            ("new_gid".into(), value.new_gid.into()),
            ("old_gid".into(), value.old_gid.into()),
        ]);

        AnyValue::Map(map)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AclTag {
    UserObj,
    User,
    GroupObj,
    Group,
    Mask,
    Other,
    Unknown(i16),
}

impl From<fact_ebpf::acl_tag_t> for AclTag {
    fn from(tag: fact_ebpf::acl_tag_t) -> Self {
        match tag {
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_USER_OBJ => AclTag::UserObj,
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_USER => AclTag::User,
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_GROUP_OBJ => AclTag::GroupObj,
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_GROUP => AclTag::Group,
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_MASK => AclTag::Mask,
            fact_ebpf::acl_tag_t::FACT_ACL_TAG_OTHER => AclTag::Other,
            other => AclTag::Unknown(other.0 as i16),
        }
    }
}

#[cfg(feature = "otel")]
impl From<AclTag> for opentelemetry::logs::AnyValue {
    fn from(value: AclTag) -> Self {
        match value {
            AclTag::UserObj => "user_obj".into(),
            AclTag::User => "user".into(),
            AclTag::GroupObj => "group_obj".into(),
            AclTag::Group => "group".into(),
            AclTag::Mask => "mask".into(),
            AclTag::Other => "other".into(),
            AclTag::Unknown(v) => format!("unknown({v})").into(),
        }
    }
}

impl AclTag {
    /// Whether this tag type carries a meaningful uid/gid.
    fn has_qualifier(&self) -> bool {
        matches!(self, AclTag::User | AclTag::Group)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclEntry {
    tag: AclTag,
    perm: u16,
    id: Option<u32>,
}

impl AclEntry {
    fn new(entry: &fact_ebpf::acl_entry_t) -> Self {
        let tag = AclTag::from(entry.e_tag);
        let id = tag.has_qualifier().then_some(entry.e_id);
        AclEntry {
            tag,
            perm: entry.e_perm,
            id,
        }
    }
}

#[cfg(feature = "otel")]
impl From<AclEntry> for opentelemetry::logs::AnyValue {
    fn from(value: AclEntry) -> Self {
        let mut map = HashMap::from([
            ("tag".into(), value.tag.into()),
            ("perm".into(), value.perm.into()),
        ]);
        if let Some(id) = value.id {
            map.insert("id".into(), id.into());
        }

        AnyValue::Map(Box::new(map))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AclType {
    Access,
    Default,
}

#[cfg(feature = "otel")]
impl From<AclType> for opentelemetry::logs::AnyValue {
    fn from(value: AclType) -> Self {
        match value {
            AclType::Access => "access".into(),
            AclType::Default => "default".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AclSetFileData {
    inner: BaseFileData,
    acl_type: AclType,
    entries: Vec<AclEntry>,
}

impl From<AclTag> for i32 {
    fn from(tag: AclTag) -> Self {
        match tag {
            AclTag::UserObj => fact_api::AclTag::UserObj as i32,
            AclTag::User => fact_api::AclTag::User as i32,
            AclTag::GroupObj => fact_api::AclTag::GroupObj as i32,
            AclTag::Group => fact_api::AclTag::Group as i32,
            AclTag::Mask => fact_api::AclTag::Mask as i32,
            AclTag::Other => fact_api::AclTag::Other as i32,
            AclTag::Unknown(_) => fact_api::AclTag::Unspecified as i32,
        }
    }
}

impl From<AclEntry> for fact_api::AclEntry {
    fn from(entry: AclEntry) -> Self {
        fact_api::AclEntry {
            tag: i32::from(entry.tag),
            perm: entry.perm as u32,
            id: entry.id.unwrap_or(u32::MAX),
        }
    }
}

impl From<AclSetFileData> for fact_api::FileAclChange {
    fn from(value: AclSetFileData) -> Self {
        let activity = fact_api::FileActivityBase::from(value.inner);
        let acl_type = match value.acl_type {
            AclType::Access => fact_api::AclType::Access as i32,
            AclType::Default => fact_api::AclType::Default as i32,
        };
        let entries = value
            .entries
            .into_iter()
            .map(fact_api::AclEntry::from)
            .collect();
        fact_api::FileAclChange {
            activity: Some(activity),
            acl_type,
            entries,
        }
    }
}

#[cfg(feature = "otel")]
impl From<AclSetFileData> for opentelemetry::logs::AnyValue {
    fn from(value: AclSetFileData) -> Self {
        let AnyValue::Map(mut map) = value.inner.into() else {
            unreachable!("new value did not serialize to map");
        };
        map.insert("acl_type".into(), value.acl_type.into());
        let entries = value
            .entries
            .into_iter()
            .map(AnyValue::from)
            .collect::<Vec<_>>();
        map.insert("entries".into(), AnyValue::ListAny(Box::new(entries)));

        AnyValue::Map(map)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XattrFileData {
    inner: BaseFileData,
    xattr_name: String,
}

impl From<XattrFileData> for fact_api::FileXattrChange {
    fn from(value: XattrFileData) -> Self {
        let activity = fact_api::FileActivityBase::from(value.inner);
        fact_api::FileXattrChange {
            activity: Some(activity),
            xattr_name: value.xattr_name,
        }
    }
}

#[cfg(feature = "otel")]
impl From<XattrFileData> for opentelemetry::logs::AnyValue {
    fn from(value: XattrFileData) -> Self {
        let AnyValue::Map(mut map) = value.inner.into() else {
            unreachable!("inner value did not serialize to map");
        };
        map.insert("xattr_name".into(), value.xattr_name.into());

        AnyValue::Map(map)
    }
}

impl PartialEq for XattrFileData {
    fn eq(&self, other: &Self) -> bool {
        self.xattr_name == other.xattr_name && self.inner == other.inner
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessData {
    Fork(ProcessForkData),
    Exec(ProcessExecData),
    Exit(ProcessExitData),
    Proc(Process),
}

impl ProcessData {
    #[cfg(feature = "otel")]
    fn event_type(&self) -> &'static str {
        use ProcessData::*;
        match self {
            Fork(_) => "fork",
            Exec(_) => "exec",
            Proc(_) => "proc",
            Exit(_) => "exit",
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
