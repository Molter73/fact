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

struct submit_event_args_t {
  struct event_t* event;
  struct metrics_by_hook_t* metrics;
  const char* filename;
  inode_key_t inode;
  inode_key_t parent_inode;
  monitored_t monitored;
};

__always_inline static bool reserve_event(struct submit_event_args_t* args) {
  args->event = bpf_ringbuf_reserve(&rb, sizeof(struct event_t), 0);
  if (args->event == NULL) {
    args->metrics->ringbuffer_full++;
    return false;
  }
  return true;
}

__always_inline static void __submit_event(struct submit_event_args_t* args) {
  args->event->timestamp = bpf_ktime_get_boot_ns();

  args->metrics->added++;
  bpf_ringbuf_submit(args->event, 0);
  return;
}

__always_inline static void __submit_file_event(struct submit_event_args_t* args,
                                                bool use_bpf_d_path) {
  struct event_t* event = args->event;
  event->timestamp = bpf_ktime_get_boot_ns();
  event->common_data.file.monitored = args->monitored;
  inode_copy(&event->common_data.file.inode, &args->inode);
  inode_copy(&event->common_data.file.parent_inode, &args->parent_inode);
  if (args->filename != NULL) {
    bpf_probe_read_str(event->common_data.file.path, PATH_MAX, args->filename);
  } else {
    event->common_data.file.path[0] = '\0';
  }

  struct helper_t* helper = get_helper();
  if (helper == NULL) {
    goto error;
  }

  struct task_struct* task = bpf_get_current_task_btf();
  int64_t err = process_fill(&event->process, task, use_bpf_d_path, true);
  if (err) {
    bpf_printk("Failed to fill process information: %d", err);
    goto error;
  }

  __submit_event(args);
  return;

error:
  args->metrics->error++;
  bpf_ringbuf_discard(event, 0);
}

__always_inline static void submit_open_event(struct submit_event_args_t* args,
                                              fact_event_type_t event_type) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = event_type;

  __submit_file_event(args, true);
}

__always_inline static void submit_link_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_LINK;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_unlink_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_UNLINK;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_mode_event(struct submit_event_args_t* args,
                                              umode_t mode,
                                              umode_t old_mode) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_CHMOD;
  args->event->chmod.new = mode;
  args->event->chmod.old = old_mode;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_ownership_event(struct submit_event_args_t* args,
                                                   unsigned long long uid,
                                                   unsigned long long gid,
                                                   unsigned long long old_uid,
                                                   unsigned long long old_gid) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_CHOWN;
  args->event->chown.new.uid = uid;
  args->event->chown.new.gid = gid;
  args->event->chown.old.uid = old_uid;
  args->event->chown.old.gid = old_gid;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_rename_event(struct submit_event_args_t* args,
                                                const char old_filename[PATH_MAX],
                                                inode_key_t* old_inode,
                                                monitored_t old_monitored) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_RENAME;
  bpf_probe_read_str(args->event->from.filename, PATH_MAX, old_filename);
  inode_copy(&args->event->from.inode, old_inode);
  args->event->from.monitored = old_monitored;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_mkdir_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = DIR_ACTIVITY_CREATION;

  // d_instantiate doesn't support bpf_d_path, so we use false and rely on the stashed path from path_mkdir
  __submit_file_event(args, false);
}

__always_inline static void submit_rmdir_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = DIR_ACTIVITY_UNLINK;

  __submit_file_event(args, path_hooks_support_bpf_d_path);
}

__always_inline static void submit_xattr_event(struct submit_event_args_t* args,
                                               fact_event_type_t event_type,
                                               const char* xattr_name) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = event_type;
  bpf_probe_read_str(args->event->xattr.name, XATTR_NAME_MAX_LEN, xattr_name);

  __submit_file_event(args, false);
}

__always_inline static void submit_acl_event(struct submit_event_args_t* args,
                                             const char* acl_name,
                                             struct posix_acl* kacl) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = FILE_ACTIVITY_ACL_SET;

  // Determine ACL type from the xattr name.
  // "system.posix_acl_access" vs "system.posix_acl_default". name_buf
  // only needs to hold the longer of the two names, 25 bytes including
  // the null terminator, rounded up to the next power of two for
  // alignment.
  char name_buf[32] = {0};
  long name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), acl_name);
  if (name_len == 25 && __builtin_memcmp(name_buf, "system.posix_acl_default", 24) == 0) {
    args->event->acl.acl_type = FACT_ACL_TYPE_DEFAULT;
  } else {
    args->event->acl.acl_type = FACT_ACL_TYPE_ACCESS;
  }

  if (kacl != NULL) {
    unsigned int count = 0;
    bpf_probe_read_kernel(&count, sizeof(count), &kacl->a_count);
    if (count > FACT_MAX_ACL_ENTRIES) {
      count = FACT_MAX_ACL_ENTRIES;
    }
    args->event->acl.count = count;

    for (unsigned int i = 0; i < FACT_MAX_ACL_ENTRIES && i < count; i++) {
      struct posix_acl_entry entry = {0};
      bpf_probe_read_kernel(&entry, sizeof(entry), &kacl->a_entries[i]);
      args->event->acl.entries[i].e_tag = (acl_tag_t)entry.e_tag;
      args->event->acl.entries[i].e_perm = entry.e_perm;
      // e_uid is only meaningful for USER/GROUP entries; the kernel
      // leaves it unset for USER_OBJ/GROUP_OBJ/MASK/OTHER, so we must
      // not read it for those tags.
      if (entry.e_tag == FACT_ACL_TAG_USER || entry.e_tag == FACT_ACL_TAG_GROUP) {
        args->event->acl.entries[i].e_id = entry.e_uid.val;
      } else {
        args->event->acl.entries[i].e_id = ACL_UNDEFINED_ID;
      }
    }
  } else {
    args->event->acl.count = 0;
  }

  // inode_set_acl does not support bpf_d_path (no struct path available)
  __submit_file_event(args, false);
}

__always_inline static void submit_mount_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_MOUNT;

  __submit_file_event(args, true);
}

__always_inline static void submit_umount_event(struct submit_event_args_t* args) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_UMOUNT;

  __submit_file_event(args, true);
}

__always_inline static void submit_move_mount_event(struct submit_event_args_t* args,
                                                    const char from_filename[PATH_MAX],
                                                    inode_key_t* from_inode,
                                                    monitored_t from_monitored) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_MOVE_MOUNT;
  bpf_probe_read_str(args->event->from.filename, PATH_MAX, from_filename);
  inode_copy(&args->event->from.inode, from_inode);
  args->event->from.monitored = from_monitored;

  __submit_file_event(args, false);
}

__always_inline static void submit_symlink_event(struct submit_event_args_t* args,
                                                 const char from_filename[PATH_MAX]) {
  if (!reserve_event(args)) {
    return;
  }
  args->event->type = FILE_ACTIVITY_SYMLINK;
  if (bpf_probe_read_str(args->event->from.filename, PATH_MAX, from_filename) <= 0) {
    args->event->from.filename[0] = '\0';
  }

  __submit_file_event(args, false);
}

__always_inline static void __submit_process_event(struct submit_event_args_t* args,
                                                   struct task_struct* task,
                                                   fact_event_type_t type) {
  if (!reserve_event(args)) {
    return;
  }

  args->event->type = type;
  process_fill(&args->event->process, task, false, false);

  __submit_event(args);
}

__always_inline static void submit_fork_event(struct submit_event_args_t* args,
                                              struct task_struct* child) {
  __submit_process_event(args, child, PROCESS_FORK);
}

__always_inline static void submit_exec_event(struct submit_event_args_t* args,
                                              struct task_struct* task) {
  __submit_process_event(args, task, PROCESS_EXEC);
}

__always_inline static void submit_exit_event(struct submit_event_args_t* args,
                                              struct task_struct* task) {
  __submit_process_event(args, task, PROCESS_EXIT);
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

__always_inline static void submit_listening_event(struct submit_event_args_t* args,
                                                   struct inet_sock* inet,
                                                   uint16_t family) {
  if (!reserve_event(args)) {
    return;
  }
  struct event_t* event = args->event;
  event->type = SOCKET_LISTEN;
  struct task_struct* task = bpf_get_current_task_btf();

  event->common_data.network.family = family;
  event->common_data.network.listen.port = ntohs(BPF_CORE_READ(inet, inet_sport));
  switch (family) {
    case AF_INET: {
      uint32_t addr = BPF_CORE_READ(inet, inet_saddr);
      __builtin_memcpy(event->common_data.network.listen.address, &addr, 4);
    } break;
    case AF_INET6: {
      uint32_t addr[4] = {0};
      BPF_CORE_READ_INTO(&addr, inet, pinet6, saddr.in6_u.u6_addr32);
      __builtin_memcpy(event->common_data.network.listen.address, &addr, 16);
    } break;
    default:
      break;
  }

  process_fill(&event->process, task, true, true);

  __submit_event(args);
}

__always_inline static void submit_accept_event(struct submit_event_args_t* args,
                                                struct inet_sock* inet,
                                                uint16_t family) {
  if (!reserve_event(args)) {
    return;
  }
  struct event_t* event = args->event;
  event->type = SOCKET_ACCEPT;
  struct task_struct* task = bpf_get_current_task_btf();

  event->common_data.network.family = family;
  event->common_data.network.accept.local.port = ntohs(BPF_CORE_READ(inet, inet_sport));
  event->common_data.network.accept.remote.port = ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport));
  switch (family) {
    case AF_INET: {
      uint32_t local_addr = BPF_CORE_READ(inet, inet_saddr);
      uint32_t remote_addr = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);
      __builtin_memcpy(event->common_data.network.accept.local.address, &local_addr, 4);
      __builtin_memcpy(event->common_data.network.accept.remote.address, &remote_addr, 4);
    } break;
    case AF_INET6: {
      uint32_t local_addr[4] = {0};
      uint32_t remote_addr[4] = {0};
      BPF_CORE_READ_INTO(&local_addr, inet, pinet6, saddr.in6_u.u6_addr32);
      BPF_CORE_READ_INTO(&remote_addr, inet, sk.__sk_common.skc_v6_daddr);
      __builtin_memcpy(event->common_data.network.accept.local.address, &local_addr, 16);
      __builtin_memcpy(event->common_data.network.accept.remote.address, &remote_addr, 16);
    } break;
    default:
      break;
  }

  process_fill(&event->process, task, true, true);

  __submit_event(args);
}
