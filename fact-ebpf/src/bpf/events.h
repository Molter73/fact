#pragma once

// clang-format off
#include "vmlinux.h"

#include "bound_path.h"
#include "inode.h"
#include "maps.h"
#include "process.h"
#include "types.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
// clang-format on

__always_inline static void __submit_event(struct event_t* event,
                                           struct metrics_by_hook_t* m,
                                           fact_event_type_t event_type) {
  event->type = event_type;
  event->timestamp = bpf_ktime_get_boot_ns();

  m->added++;
  bpf_ringbuf_submit(event, 0);
  return;
}

__always_inline static void __submit_file_event(struct event_t* event,
                                                struct metrics_by_hook_t* m,
                                                fact_event_type_t event_type,
                                                const char filename[PATH_MAX],
                                                inode_key_t* inode,
                                                bool use_bpf_d_path) {
  inode_copy_or_reset(&event->common_data.file.inode, inode);
  bpf_probe_read_str(event->common_data.file.path, PATH_MAX, filename);

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    goto error;
  }

  struct task_struct* task = bpf_get_current_task_btf();
  int64_t err = process_fill(&event->process, task, use_bpf_d_path);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  __submit_event(event, m, event_type);
  return;

error:
  m->error++;
  bpf_ringbuf_discard(event, 0);
}

__always_inline static void submit_open_event(struct metrics_by_hook_t* m,
                                              fact_event_type_t event_type,
                                              const char filename[PATH_MAX],
                                              inode_key_t* inode) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  __submit_file_event(event, m, event_type, filename, inode, true);
}

__always_inline static void submit_unlink_event(struct metrics_by_hook_t* m,
                                                const char filename[PATH_MAX],
                                                inode_key_t* inode) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  __submit_file_event(event, m, FILE_ACTIVITY_UNLINK, filename, inode, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_mode_event(struct metrics_by_hook_t* m,
                                              const char filename[PATH_MAX],
                                              inode_key_t* inode,
                                              umode_t mode,
                                              umode_t old_mode) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->chmod.new = mode;
  event->chmod.old = old_mode;

  __submit_file_event(event, m, FILE_ACTIVITY_CHMOD, filename, inode, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_ownership_event(struct metrics_by_hook_t* m,
                                                   const char filename[PATH_MAX],
                                                   inode_key_t* inode,
                                                   unsigned long long uid,
                                                   unsigned long long gid,
                                                   unsigned long long old_uid,
                                                   unsigned long long old_gid) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  event->chown.new.uid = uid;
  event->chown.new.gid = gid;
  event->chown.old.uid = old_uid;
  event->chown.old.gid = old_gid;

  __submit_file_event(event, m, FILE_ACTIVITY_CHOWN, filename, inode, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_rename_event(struct metrics_by_hook_t* m,
                                                const char new_filename[PATH_MAX],
                                                const char old_filename[PATH_MAX],
                                                inode_key_t* new_inode,
                                                inode_key_t* old_inode) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  bpf_probe_read_str(event->rename.old_filename, PATH_MAX, old_filename);
  inode_copy_or_reset(&event->rename.old_inode, old_inode);

  __submit_file_event(event, m, FILE_ACTIVITY_RENAME, new_filename, new_inode, path_hooks_support_bpf_d_path);
}

__always_inline static void __submit_process_event(struct metrics_by_hook_t* m,
                                                   const struct task_struct* task,
                                                   fact_event_type_t type) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }

  process_fill(&event->process, task, false);

  __submit_event(event, m, type);
}
__always_inline static void submit_fork_event(struct metrics_by_hook_t* m,
                                              const struct task_struct* child) {
  __submit_process_event(m, child, PROCESS_FORK);
}

__always_inline static void submit_exec_event(struct metrics_by_hook_t* m,
                                              const struct task_struct* task) {
  __submit_process_event(m, task, PROCESS_EXEC);
}

__always_inline static void submit_exit_event(struct metrics_by_hook_t* m,
                                              const struct task_struct* task) {
  __submit_process_event(m, task, PROCESS_EXIT);
}

// Taken from the kernel headers directly
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

#define swap16(x) ((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8)
#define swap32(x) ((x & 0xFF000000) >> 24) |    \
                      ((x & 0x00FF0000) >> 8) | \
                      ((x & 0x0000FF00) << 8) | \
                      ((x & 0x000000FF) << 24)

#ifdef __LITTLE_ENDIAN__
#  define ntohs(x) swap16(x)
#  define ntohl(x) swap32(x)
#else
#  define ntohs(x) x
#  define ntohl(x) x
#endif
__always_inline static void submit_listening_event(struct metrics_by_hook_t* m,
                                                   struct inet_sock* inet,
                                                   uint16_t family) {
  struct event_t* event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (event == NULL) {
    m->ringbuffer_full++;
    return;
  }
  const struct task_struct* task = bpf_get_current_task_btf();

  event->common_data.listen.family = family;
  event->common_data.listen.port = ntohs(BPF_CORE_READ(inet, inet_sport));
  switch (family) {
    case AF_INET: {
      uint32_t addr = BPF_CORE_READ(inet, inet_saddr);
      __builtin_memcpy(event->common_data.listen.address, &addr, 4);
    } break;
    case AF_INET6: {
      uint32_t addr[4] = {0};
      BPF_CORE_READ_INTO(&addr, inet, pinet6, saddr.in6_u.u6_addr32);
      __builtin_memcpy(event->common_data.listen.address, &addr, 16);
    } break;
    default:
      break;
  }

  process_fill(&event->process, task, true);

  __submit_event(event, m, SOCKET_LISTEN);
}
