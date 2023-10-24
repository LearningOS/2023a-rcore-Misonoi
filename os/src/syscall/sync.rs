use crate::sync::{Condvar, Mutex, MutexBlocking, MutexSpin, Semaphore};
use crate::task::{block_current_and_run_next, current_process, current_task, /*TaskStatus*/};
use crate::timer::{add_timer, get_time_ms};
use alloc::sync::Arc;
use alloc::vec::Vec;
/// sleep syscall
pub fn sys_sleep(ms: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_sleep",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let expire_ms = get_time_ms() + ms;
    let task = current_task().unwrap();
    add_timer(expire_ms, task);
    block_current_and_run_next();
    0
}
/// mutex create syscall
pub fn sys_mutex_create(blocking: bool) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_mutex_create",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let mutex: Option<Arc<dyn Mutex>> = if !blocking {
        Some(Arc::new(MutexSpin::new()))
    } else {
        Some(Arc::new(MutexBlocking::new()))
    };
    let mut process_inner = process.inner_exclusive_access();
    if let Some(id) = process_inner
        .mutex_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.mutex_list[id] = mutex;
        process_inner.mutex_available[id] = 1;
        for need in process_inner.mutex_need.iter_mut() {
            need[id] = 0;
        }
        for allocated in process_inner.mutex_allocated.iter_mut() {
            allocated[id] = 0;
        }
        id as isize
    } else {
        process_inner.mutex_list.push(mutex);
        process_inner.mutex_available.push(1);
        for need in process_inner.mutex_need.iter_mut() {
            need.push(0);
        }
        for allocated in process_inner.mutex_allocated.iter_mut() {
            allocated.push(0);
        }
        process_inner.mutex_list.len() as isize - 1
    }
}
/// mutex lock syscall
pub fn sys_mutex_lock(mutex_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_mutex_lock",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    let task_id = current_task().unwrap().inner_exclusive_access().res.as_ref().unwrap().tid;
    process_inner.mutex_need[task_id][mutex_id] += 1;
    if process_inner.is_detect_deadlock_enable {
        let mut finished = Vec::new();
        let total_task_num = process_inner.mutex_need.len();
        for _ in 0..total_task_num {
            finished.push(false);
        }
        let mut work = process_inner.mutex_available.clone();
        
        loop {
            let mut updateable = false;
            for task_index in 0..total_task_num {
                if finished[task_index] == false {
                    let mut cant_finish = false;
                    for (mutex_index, _) in work.iter().enumerate() {
                        if process_inner.mutex_need[task_index][mutex_index] > work[mutex_index] {
                            cant_finish = true;
                            break;
                        }
                    }
                    if !cant_finish {
                        finished[task_index] = true;
                        for (mutex_index, work_content) in work.iter_mut().enumerate() {
                            *work_content += process_inner.mutex_allocated[task_index][mutex_index];
                            }
                        updateable = true;
                    }
                }
            }
            if updateable == false {
                break;
            }
        }
        let mut is_deadlocked = false;
        for finish_status in finished {
            if finish_status == false {
                is_deadlocked = true;
                break;
            }
        }
        if is_deadlocked {
            process_inner.mutex_need[task_id][mutex_id] -= 1;
            return -0xDEAD;
        }
    }
    drop(process_inner);
    drop(process);
    mutex.lock();
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    process_inner.mutex_need[task_id][mutex_id] -= 1;
    process_inner.mutex_available[mutex_id] -= 1;
    process_inner.mutex_allocated[task_id][mutex_id] += 1;
    0
}
/// mutex unlock syscall
pub fn sys_mutex_unlock(mutex_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_mutex_unlock",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let task_id = current_task().unwrap().inner_exclusive_access().res.as_ref().unwrap().tid;
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    process_inner.mutex_allocated[task_id][mutex_id] -= 1;
    process_inner.mutex_available[mutex_id] += 1;
    drop(process_inner);
    drop(process);
    mutex.unlock();
    0
}
/// semaphore create syscall
pub fn sys_semaphore_create(res_count: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_semaphore_create",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .semaphore_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.semaphore_list[id] = Some(Arc::new(Semaphore::new(res_count)));
        process_inner.semaphore_available[id] = res_count;
        for need in process_inner.semaphore_need.iter_mut() {
            need[id] = 0;
        }
        for allocated in process_inner.semaphore_allocated.iter_mut() {
            allocated[id] = 0;
        }
        id
    } else {
        process_inner
            .semaphore_list
            .push(Some(Arc::new(Semaphore::new(res_count))));
        process_inner.semaphore_available.push(res_count);
        for need in process_inner.semaphore_need.iter_mut() {
            need.push(0);
        }
        for allocated in process_inner.semaphore_allocated.iter_mut() {
            allocated.push(0);
        }
        process_inner.semaphore_list.len() - 1
    };
    id as isize
}
/// semaphore up syscall
pub fn sys_semaphore_up(sem_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_semaphore_up",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let task_id = current_task().unwrap().inner_exclusive_access().res.as_ref().unwrap().tid;
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    process_inner.semaphore_allocated[task_id][sem_id] -= 1;
    process_inner.semaphore_available[sem_id] += 1;
    drop(process_inner);
    sem.up();
    0
}
/// semaphore down syscall
pub fn sys_semaphore_down(sem_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_semaphore_down",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    let task_id = current_task().unwrap().inner_exclusive_access().res.as_ref().unwrap().tid;
    process_inner.semaphore_need[task_id][sem_id] += 1;
    if process_inner.is_detect_deadlock_enable {
        let mut finished = Vec::new();
        let total_task_num = process_inner.semaphore_need.len();
        for _ in 0..total_task_num {
            finished.push(false);
        }
        let mut work = process_inner.semaphore_available.clone();
        
        loop {
            let mut updateable = false;
            for task_index in 0..total_task_num {
                if finished[task_index] == false {
                    let mut cant_finish = false;
                    for (sem_index, _) in work.iter().enumerate() {
                        if process_inner.semaphore_need[task_index][sem_index] > work[sem_index] {
                            cant_finish = true;
                            break;
                        }
                    }
                    if !cant_finish {
                        finished[task_index] = true;
                        for (sem_index, work_content) in work.iter_mut().enumerate() {
                            *work_content += process_inner.semaphore_allocated[task_index][sem_index];
                            }
                        updateable = true;
                    }
                }
            }
            if updateable == false {
                break;
            }
        }
        let mut is_deadlocked = false;
        for finish_status in finished {
            if finish_status == false {
                is_deadlocked = true;
                break;
            }
        }
        if is_deadlocked {
            process_inner.semaphore_need[task_id][sem_id] -= 1;
            return -0xDEAD;
        }
    }
    drop(process_inner);
    sem.down();
    let mut process_inner = process.inner_exclusive_access();
    process_inner.semaphore_need[task_id][sem_id] -= 1;
    process_inner.semaphore_available[sem_id] -= 1;
    process_inner.semaphore_allocated[task_id][sem_id] += 1;
    0
}
/// condvar create syscall
pub fn sys_condvar_create() -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_condvar_create",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .condvar_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.condvar_list[id] = Some(Arc::new(Condvar::new()));
        id
    } else {
        process_inner
            .condvar_list
            .push(Some(Arc::new(Condvar::new())));
        process_inner.condvar_list.len() - 1
    };
    id as isize
}
/// condvar signal syscall
pub fn sys_condvar_signal(condvar_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_condvar_signal",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    drop(process_inner);
    condvar.signal();
    0
}
/// condvar wait syscall
pub fn sys_condvar_wait(condvar_id: usize, mutex_id: usize) -> isize {
    trace!(
        "kernel:pid[{}] tid[{}] sys_condvar_wait",
        current_task().unwrap().process.upgrade().unwrap().getpid(),
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .res
            .as_ref()
            .unwrap()
            .tid
    );
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    drop(process_inner);
    condvar.wait(mutex);
    0
}
/// enable deadlock detection syscall
///
/// YOUR JOB: Implement deadlock detection, but might not all in this syscall
pub fn sys_enable_deadlock_detect(enabled: usize) -> isize {
    trace!("kernel: sys_enable_deadlock_detect");
    if enabled == 0 {
        current_process().inner_exclusive_access().is_detect_deadlock_enable = false;
        0
    } else if enabled == 1 {
        current_process().inner_exclusive_access().is_detect_deadlock_enable = true;
        0
    } else {
        -1
    }
}
