#pragma once

// clang-format off
#include "vmlinux.h"

#include "maps.h"

#include <bpf/bpf_helpers.h>
// clang-format on

__always_inline static uint64_t get_upid(const struct task_struct* task) {
  static uint64_t global_upid = 1;
  uint64_t upid_id = 0;

  // The upid is always assigned to the group_leader
  bpf_rcu_read_lock();
  struct task_struct* group_leader = bpf_task_acquire(task->group_leader);
  bpf_rcu_read_unlock();
  if (group_leader == NULL) {
    goto end;
  }

  struct upid_t* upid = bpf_task_storage_get(&task_upid_map, group_leader, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (upid == NULL) {
    goto end;
  }

  if (upid->id != 0) {
    upid_id = upid->id;
    goto end;
  }

  bpf_spin_lock(&upid->semaphore);
  // Check again in case some other thread updated the value under us.
  if (upid->id == 0) {
    upid->id = __sync_fetch_and_add(&global_upid, 1);
  }
  bpf_spin_unlock(&upid->semaphore);
  upid_id = upid->id;

end:
  if (group_leader != NULL) {
    bpf_task_release(group_leader);
  }
  return upid_id;
}

__always_inline static uint64_t get_parent_upid(const struct task_struct* task) {
  uint64_t upid = 0;
  bpf_rcu_read_lock();
  struct task_struct* parent = bpf_task_acquire(task->real_parent);
  bpf_rcu_read_unlock();
  if (parent == NULL) {
    goto cleanup;
  }

  upid = get_upid(parent);

cleanup:
  if (parent != NULL) {
    bpf_task_release(parent);
  }
  return upid;
}
