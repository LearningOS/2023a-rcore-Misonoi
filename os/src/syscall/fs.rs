//! File and filesystem-related syscalls
use crate::fs::{open_file, OpenFlags, Stat};
use crate::fs::inode::ROOT_INODE;
use crate::mm::{translated_byte_buffer, translated_refmut, translated_str, UserBuffer};
use crate::sbi::console_getchar;
use crate::syscall::process::LAB_MANAGER;
use crate::syscall::SYSCALL_WRITE;
use crate::task::{current_task, current_user_token, suspend_current_and_run_next};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    LAB_MANAGER.exclusive_access().update_syscall(SYSCALL_WRITE);

    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(_fd: usize, _st: *mut Stat) -> isize {
    trace!(
        "kernel:pid[{}] sys_fstat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    let binding = current_task();
    let task = binding.as_ref().unwrap();

    let token = task.inner_exclusive_access().get_user_token();

    let binding = task.inner_exclusive_access();
    let file = binding.fd_table[_fd].as_ref().unwrap();

    let (ino, mode, nlink) = (file.get_inode_id(), file.get_mode(), file.get_nlink());

    println!("RefCell I Fuck youuuuuuuuuuuuuuuu");
    let st_ref = translated_refmut(token, _st);

    *st_ref = Stat {
        dev: 0,
        ino,
        mode,
        nlink,
        pad: [0; 7],
    };

    0
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_linkat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    ROOT_INODE.link(
        translated_str(current_user_token(), _old_name).as_str(),
        translated_str(current_user_token(), _new_name).as_str(),
    )
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(_name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_unlinkat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );

    ROOT_INODE.unlink(translated_str(current_user_token(), _name).as_str())
}
