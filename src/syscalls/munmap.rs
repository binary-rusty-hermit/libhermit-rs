use crate::arch;
use crate::arch::mm::paging::{
        BasePageSize, HugePageSize, LargePageSize, PageSize, PageTableEntryFlags,
};
use crate::arch::mm::{VirtAddr};
use crate::mm::deallocate;

const PROT_NONE: i32 =  0x0;
const PROT_READ: i32 =  0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 =  0x4;

const MAP_SHARED: i32 = 0x01;
const MAP_PRIVATE: i32 = 0x02;

const MAP_ANONYMOUS: i32 = 0x20;

#[no_mangle]
pub fn sys_munmap(addr: *const usize, len: usize) -> usize {
        kernel_function!(__sys_munmap(addr, len))
}

unsafe fn __sys_munmap(addr: *const usize, len: usize) -> usize {
        println!("Here in munmap, addr: {}, len: {}", addr as usize, len);

	let size = align_up!(len, BasePageSize::SIZE);
	
	let virtAddr: VirtAddr = VirtAddr::from_usize(addr as usize);
	deallocate(virtAddr, size);
	
	arch::mm::physicalmem::print_information();
        arch::mm::virtualmem::print_information();

	return 0 as usize;
}
