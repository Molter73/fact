#pragma once

/**
 * This file is used to generate bindings to the Rust side and needs to
 * be kept as minimal as possible, avoid including vmlinux.h or any
 * other sources of bloat into this file.
 */

/**
 * Kernel constant, taken from:
 * https://github.com/torvalds/linux/blob/f0b9d8eb98dfee8d00419aa07543bdc2c1a44fb1/include/uapi/linux/limits.h#L13
 */
#define PATH_MAX 4096
#define TASK_COMM_LEN 16

#define LPM_SIZE_MAX 256

typedef struct process_t {
  char comm[TASK_COMM_LEN];
  char args[4096];
  unsigned int args_len;
  char exe_path[PATH_MAX];
  char memory_cgroup[PATH_MAX];
  unsigned int uid;
  unsigned int gid;
  unsigned int login_uid;
  unsigned int pid;
  char in_root_mount_ns;
  unsigned long upid;
  unsigned long parent_upid;
} process_t;

typedef struct inode_key_t {
  unsigned long inode;
  unsigned long dev;
} inode_key_t;

// We can't use bool here because it is not a standard C type, we would
// need to include vmlinux.h but that would explode our Rust bindings.
// For the time being we just keep a char.
typedef char inode_value_t;

typedef enum fact_event_type_t {
  FILE_ACTIVITY_INIT = -1,
  FILE_ACTIVITY_OPEN = 0,
  FILE_ACTIVITY_CREATION,
  FILE_ACTIVITY_UNLINK,
  FILE_ACTIVITY_CHMOD,
  FILE_ACTIVITY_CHOWN,
  FILE_ACTIVITY_RENAME,
  PROCESS_FORK,
  PROCESS_EXEC,
  PROCESS_EXIT,
  SOCKET_LISTEN,
} fact_event_type_t;

struct event_t {
  unsigned long timestamp;
  process_t process;
  fact_event_type_t type;
  union {
    struct {
      char path[PATH_MAX];
      inode_key_t inode;
    } file;
    struct {
      unsigned short family;
      unsigned char address[16];
      unsigned short port;
    } listen;
  } common_data;
  union {
    struct {
      short unsigned int new;
      short unsigned int old;
    } chmod;
    struct {
      struct {
        unsigned int uid;
        unsigned int gid;
      } old, new;
    } chown;
    struct {
      char old_filename[PATH_MAX];
      inode_key_t old_inode;
    } rename;
  };
};

/**
 * Used as the key for the path_prefix map.
 *
 * The memory layout is specific and must always have a 4 byte length
 * field first.
 *
 * See https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LPM_TRIE/
 * for a detailed description of how the LPM map works.
 */
struct path_prefix_t {
  unsigned int bit_len;
  const char path[LPM_SIZE_MAX];
};

// Metrics types
struct metrics_by_hook_t {
  unsigned long long total;
  unsigned long long added;
  unsigned long long error;
  unsigned long long ignored;
  unsigned long long ringbuffer_full;
};

struct metrics_t {
  struct metrics_by_hook_t file_open;
  struct metrics_by_hook_t path_unlink;
  struct metrics_by_hook_t path_chmod;
  struct metrics_by_hook_t path_chown;
  struct metrics_by_hook_t path_rename;
  struct metrics_by_hook_t sched_fork;
  struct metrics_by_hook_t sched_exec;
  struct metrics_by_hook_t sched_exit;
  struct metrics_by_hook_t iter_task;
  struct metrics_by_hook_t socket_listen;
};
