#pragma once

// clang-format off
#include "vmlinux.h"

#include "maps.h"

#include <bpf/bpf_helpers.h>
// clang-format on

__always_inline static uint64_t get_upid(const struct task_struct* task) {
  static uint64_t global_upid = 1;

  // The upid is always assigned to the group_leader
  struct task_struct* group_leader = task->group_leader;
  if (group_leader == NULL) {
    return 0;
  }

  struct upid_t* upid = bpf_task_storage_get(&task_upid_map, group_leader, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (upid == NULL) {
    return 0;
  }

  if (upid->id != 0) {
    return upid->id;
  }

  bpf_spin_lock(&upid->semaphore);
  // Check again in case some other thread updated the value under us.
  if (upid->id == 0) {
    upid->id = __sync_fetch_and_add(&global_upid, 1);
  }
  bpf_spin_unlock(&upid->semaphore);

  return upid->id;
}

__always_inline static uint64_t get_parent_upid(const struct task_struct* task) {
  struct task_struct* parent = task->real_parent;
  if (parent == NULL) {
    return 0;
  }

  return get_upid(parent);
}
