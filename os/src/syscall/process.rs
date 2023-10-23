//! Process management syscalls
use alloc::sync::Arc;
use lazy_static::lazy_static;

use crate::{
    config::MAX_SYSCALL_NUM,
    loader::get_app_data_by_name,
    mm::{translated_refmut, translated_str},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus,
    },
};
use crate::config::PAGE_SIZE;
use crate::mm::{MapPermission, MemorySet, VirtAddr, VirtPageNum};
use crate::mm::memory_set::{MapArea, MapType};
use crate::sync::UPSafeCell;
use crate::syscall::{SYSCALL_EXIT, SYSCALL_GET_TIME, SYSCALL_TASK_INFO, SYSCALL_YIELD};
use crate::task::processor::current_pid;
use crate::task::TaskControlBlock;
use crate::timer::{get_time_ms, get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

pub struct LabManager {
    task_info: [TaskInfo; 60],
    is_already_running: [bool; 120],
}

impl LabManager {
    pub fn new() -> Self {
        Self {
            task_info: [TaskInfo {
                status: TaskStatus::Running,
                syscall_times: [0; MAX_SYSCALL_NUM],
                time: 0,
            }; 60],
            is_already_running: [false; 120],
        }
    }

    pub fn update_syscall(&mut self, id: usize) {
        let pid = current_pid();

        self.task_info[pid].syscall_times[id] += 1;
    }

    pub fn update_task_info(&mut self, pid: usize) {
        if self.is_already_running[pid] == false {
            self.is_already_running[pid] = true;
            self.task_info[pid].time = get_time_ms();
        }
    }

    pub fn current_task_info(&mut self, pid: usize) -> TaskInfo {
        self.task_info[pid].clone()
    }

    pub fn _sys_mmap(&self, _start: usize, _len: usize, _port: usize) -> isize {
        if _start % PAGE_SIZE != 0 || _port & !0x7 != 0 || _port & 0x7 == 0 {
            return -1;
        }

        let start_va = VirtAddr::from(_start);
        let end_va = VirtAddr::from(_start + _len);

        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();

        let end_va = VirtAddr::from(end_vpn);

        let binding = current_task();
        let memory_set_ref_mut = &mut binding.as_ref().unwrap().inner_exclusive_access().memory_set;

        if (start_vpn.0..end_vpn.0).any(|e| Self::is_mapped(memory_set_ref_mut, VirtPageNum::from(e))) {
            return -1;
        }

        let flag = MapPermission::from_bits((_port << 1 | 16) as u8).unwrap();

        memory_set_ref_mut.insert_framed_area(start_va, end_va, flag);

        0
    }

    pub fn search_area_index(set: &MemorySet, start_vpn: VirtPageNum, end_vpn: VirtPageNum) -> usize {
        set.areas.iter().enumerate().find(|(idx, e)| {
            e.vpn_range.get_start() == start_vpn && e.vpn_range.get_end() == end_vpn
        }).unwrap_or((usize::MAX, &MapArea::new(VirtAddr::from(0),
                                                VirtAddr::from(0),
                                                MapType::Identical, MapPermission::empty()))).0
    }

    pub fn dealloc(set: &mut MemorySet, idx: usize) {
        let area = &mut set.areas[idx];

        area.unmap(&mut set.page_table);

        set.areas.remove(idx);
    }

    pub fn dealloc_precious(set: &mut MemorySet, start_von: VirtPageNum, end_vpn: VirtPageNum) {
        let idx = Self::search_area_index(set ,start_von, end_vpn);

        if idx != usize::MAX {
            Self::dealloc(set, idx)
        }
    }

    pub fn _sys_munmap(&self, _start: usize, _len: usize) -> isize {
        if _start % 1024 != 0 {
            return -1;
        }

        let start_va = VirtAddr::from(_start);
        let end_va = VirtAddr::from(_start + _len);

        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();

        let start_va = VirtAddr::from(start_vpn);
        let end_va = VirtAddr::from(end_vpn);

        let binding = current_task();
        let memory_set_ref_mut = &mut binding.as_ref().unwrap().inner_exclusive_access().memory_set;

        if (start_vpn.0..end_vpn.0).any(|e| !Self::is_mapped(memory_set_ref_mut, VirtPageNum::from(e))) {
            return -1;
        }

        Self::dealloc_precious(memory_set_ref_mut, start_vpn, end_vpn);

        0
    }

    pub fn is_mapped(set: &MemorySet, vpn: VirtPageNum) -> bool {
        set.page_table.find_pte(vpn).is_some() && set.page_table.find_pte(vpn).unwrap().is_valid()
    }
}

lazy_static! {
    pub static ref LAB_MANAGER: UPSafeCell<LabManager> = unsafe {
        UPSafeCell::new(LabManager::new())
    };
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    LAB_MANAGER.exclusive_access().update_syscall(SYSCALL_EXIT);

    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    LAB_MANAGER.exclusive_access().update_syscall(SYSCALL_YIELD);

    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    LAB_MANAGER.exclusive_access().update_syscall(SYSCALL_GET_TIME);

    trace!(
        "kernel:pid[{}] sys_get_time NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    let time = get_time_us();

    let ts_ptr = translated_refmut(current_user_token(), _ts);

    *ts_ptr = TimeVal {
        sec: time / 1_000_000,
        usec: time % 1_000_000,
    };

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    LAB_MANAGER.exclusive_access().update_syscall(SYSCALL_TASK_INFO);

    trace!(
        "kernel:pid[{}] sys_task_info NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    unsafe {
        *_ti = LAB_MANAGER.exclusive_access().current_task_info(
            current_task().unwrap().pid.0
        )
    }

    0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    LAB_MANAGER.exclusive_access()._sys_mmap(_start, _len, _port)
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    LAB_MANAGER.exclusive_access()._sys_munmap(_start, _len)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    let file_name = translated_str(current_user_token(), _path);
    let data = get_app_data_by_name(file_name.as_str());

    if data.is_none() {
        return -1;
    }

    let block = TaskControlBlock::new(data.unwrap());
    let pid = block.pid.0;

    let binding = current_task().unwrap();
    let mut task = binding.inner_exclusive_access();

    let children_block = Arc::new(block);

    task.children.push(Arc::clone(&children_block));
    add_task(children_block);

    pid as isize
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    if _prio <= 1 {
        return -1;
    }

    let binding = current_task();
    binding.as_ref().unwrap().inner_exclusive_access().priority = _prio as usize;

    _prio
}
