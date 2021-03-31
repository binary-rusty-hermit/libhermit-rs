use crate::errno::*;

use crate::arch;
use crate::arch::mm::paging::{
	BasePageSize, HugePageSize, LargePageSize, PageSize, PageTableEntryFlags,
};

const PROT_NONE: i32 =	0x0;
const PROT_READ: i32 =	0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 =	0x4;

const MAP_SHARED: i32 = 0x01;
const MAP_PRIVATE: i32 = 0x02;

const MAP_ANONYMOUS: i32 = 0x20;

#[no_mangle]
pub fn sys_mmap(addr: *const usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> usize {
        kernel_function!(__sys_mmap(addr, len, prot, flags, fd, offset))
}

unsafe fn __sys_mmap(addr: *const usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> usize {
	println!("Here in mmap, addr: {}, len: {}, prot: {}, flags: {}, fd: {}, offset: {}", addr as usize, len, prot, flags, fd, offset);	
	if addr as usize != 0x0 {
		info!("MMAP: Address is not NULL");
		return -ENOSYS as usize;
	}

	if flags & MAP_PRIVATE == 0 {
		info!("MMAP: non private mappings are not supported");
		return -ENOSYS as usize;
	}

	if flags & MAP_ANONYMOUS == 0 { 
		info!("MMAP: MAP_ANONYMOUS is currently only supported");
		return -ENOSYS as usize;
	}

	if fd != -1 {
		info!("MMAP: fd should be -1 for MAP_ANONYMOUS");
		return -EBADF as usize;
	}

	if offset != 0 {
                info!("MMAP: offset should be 0 for MAP_ANONYMOUS");
                return -EINVAL as usize;
        }

	if len == 0 {
		info!("MMAP: legnth should not be 0");
		return -EINVAL as usize;
	}

	if prot & PROT_EXEC != 0 {
		info!("MMAP: PROT_EXEC not supported currently");
                return -ENOSYS as usize;
	}
	

	arch::mm::physicalmem::print_information();
	arch::mm::virtualmem::print_information();	

	let size = align_up!(len, BasePageSize::SIZE);

	let physical_address = arch::mm::physicalmem::allocate(size).unwrap();
	let virtual_address = arch::mm::virtualmem::allocate(size).unwrap();

	let count = size / BasePageSize::SIZE;

	let mut flags = PageTableEntryFlags::empty();

	flags.normal();	// ?
	if prot & PROT_WRITE != 0 { flags.writable(); } 

	println!("\n");

	arch::mm::paging::map::<BasePageSize>(virtual_address, physical_address, count, flags);

	arch::mm::physicalmem::print_information();
	arch::mm::virtualmem::print_information();

	virtual_address.as_u64() as usize
}
