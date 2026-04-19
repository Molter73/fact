#![allow(dead_code, non_camel_case_types)]

use std::{error::Error, ffi::c_char, fmt::Display, hash::Hash, path::PathBuf};

use aya::{maps::lpm_trie, Pod};
use libc::memcpy;
use serde::{ser::SerializeStruct, Serialize};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Debug)]
pub struct PathPrefixError {
    prefix: String,
}

impl Error for PathPrefixError {}

impl Display for PathPrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid prefix: {}", self.prefix)
    }
}

impl TryFrom<&PathBuf> for path_prefix_t {
    type Error = PathPrefixError;

    fn try_from(value: &PathBuf) -> Result<Self, PathPrefixError> {
        let Some(filename) = value.to_str() else {
            return Err(PathPrefixError {
                prefix: value.display().to_string(),
            });
        };
        let len = if filename.len() > LPM_SIZE_MAX as usize {
            LPM_SIZE_MAX as usize
        } else {
            filename.len()
        };

        unsafe {
            let mut cfg: path_prefix_t = std::mem::zeroed();
            memcpy(
                cfg.path.as_mut_ptr() as *mut _,
                filename.as_ptr() as *const _,
                len,
            );
            cfg.bit_len = (len * 8) as u32;
            Ok(cfg)
        }
    }
}

impl From<path_prefix_t> for lpm_trie::Key<[c_char; LPM_SIZE_MAX as usize]> {
    fn from(value: path_prefix_t) -> Self {
        lpm_trie::Key::new(value.bit_len, value.path)
    }
}

impl PartialEq for path_prefix_t {
    fn eq(&self, other: &Self) -> bool {
        self.bit_len == other.bit_len && self.path == other.path
    }
}

unsafe impl Pod for path_prefix_t {}

impl PartialEq for inode_key_t {
    fn eq(&self, other: &Self) -> bool {
        self.inode == other.inode && self.dev == other.dev
    }
}

impl Eq for inode_key_t {}

impl Hash for inode_key_t {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inode.hash(state);
        self.dev.hash(state);
    }
}

impl Serialize for inode_key_t {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("inode_key_t", 2)?;
        state.serialize_field("inode", &self.inode)?;
        state.serialize_field("dev", &self.dev)?;
        state.end()
    }
}

unsafe impl Pod for inode_key_t {}

impl metrics_by_hook_t {
    fn accumulate(mut self, other: &metrics_by_hook_t) -> metrics_by_hook_t {
        self.total += other.total;
        self.added += other.added;
        self.error += other.error;
        self.ignored += other.ignored;
        self.ringbuffer_full += other.ringbuffer_full;

        self
    }
}

impl metrics_t {
    pub fn accumulate(mut self, other: &metrics_t) -> metrics_t {
        self.file_open = self.file_open.accumulate(&other.file_open);
        self.path_unlink = self.path_unlink.accumulate(&other.path_unlink);
        self.path_chmod = self.path_chmod.accumulate(&other.path_chmod);
        self.path_chown = self.path_chown.accumulate(&other.path_chown);
        self.path_rename = self.path_rename.accumulate(&other.path_rename);
        self.sched_fork = self.sched_fork.accumulate(&other.sched_fork);
        self.sched_exec = self.sched_exec.accumulate(&other.sched_exec);
        self.sched_exit = self.sched_exit.accumulate(&other.sched_exit);
        self.iter_task = self.iter_task.accumulate(&other.iter_task);
        self.socket_listen = self.socket_listen.accumulate(&other.socket_listen);
        self
    }
}

unsafe impl Pod for metrics_t {}

pub const EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/main.o"));
pub const CHECKS_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/checks.o"));
