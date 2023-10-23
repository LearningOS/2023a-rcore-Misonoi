//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    task::{
        change_program_brk, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus,
    },
};
use crate::config::PAGE_SIZE;
use crate::mm::memory_set::{_sys_mmap, _sys_munmap, MapArea, MapType};
use crate::mm::page_table::{PageTable, translated_ref_mut};
use crate::mm::{MapPermission, VirtAddr, VirtPageNum};
use crate::syscall::{SYSCALL_EXIT, SYSCALL_GET_TIME, SYSCALL_MMAP, SYSCALL_MUNMAP, SYSCALL_SBRK, SYSCALL_TASK_INFO, SYSCALL_YIELD};
use crate::task::{cp_current_task_info, current_task_control_block_ref_mut, current_user_token, update_syscall};
use crate::timer::{get_time_ms, get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

impl TaskInfo {
    pub fn new() -> Self {
        Self {
            status: TaskStatus::Running,
            syscall_times: [0; MAX_SYSCALL_NUM],
            time: 0,
        }
    }
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    update_syscall(SYSCALL_EXIT);

    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    update_syscall(SYSCALL_YIELD);

    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    update_syscall(SYSCALL_GET_TIME);

    trace!("kernel: sys_get_time");

    let time = get_time_us();

    let ts_mut = translated_ref_mut(current_user_token(), _ts);

    unsafe {
        *ts_mut = TimeVal {
            sec: time / 1_000_000,
            usec: time % 1_000_000,
        }
    }

    0
}

fn _sys_task_info() -> TaskInfo {
    let mut info = cp_current_task_info();

    // println!("sys_task_info, current_micro_time: {}, current_mili_time:{},  info.time: {}", get_time_us(), get_time_ms(), info.time);

    info.time = get_time_ms() - info.time;

    // println!("{:#?}", info);

    info
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    update_syscall(SYSCALL_TASK_INFO);

    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");

    let ti_mut = translated_ref_mut(current_user_token(), _ti);

    unsafe {
        // println!("{:#?}", _sys_task_info());

        *ti_mut = _sys_task_info();
    }

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    update_syscall(SYSCALL_MMAP);

    if _start % PAGE_SIZE != 0 || _port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }

    _sys_mmap(_start, _len, _port)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    update_syscall(SYSCALL_MUNMAP);

    if _start % PAGE_SIZE != 0 {
        return -1;
    }

    _sys_munmap(_start, _len)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    update_syscall(SYSCALL_SBRK);

    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
