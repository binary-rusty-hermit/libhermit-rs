#[no_mangle]
pub fn sys_mprotect(addr: *const usize, len: usize, prot: i32) -> usize {
        kernel_function!(__sys_mprotect(addr, len, prot))
}

unsafe fn __sys_mprotect(addr: *const usize, len: usize, prot: i32) -> usize {

	info!("mprotect: unsupported syscall, faking success\n");	
        return 0 as usize;
}


