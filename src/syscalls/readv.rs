use crate::errno::*;
use core::slice;
use crate::syscalls::SYS;
use alloc::string::String;

#[repr(C)]
pub struct iovec {
    pub iov_base: *mut u8,
    pub iov_len: usize,
}

fn __sys_readv(fd: i32, iov: usize, vlen: i32) -> isize {
	// iov is the pointer to the first iovec within the array
	

		let mut bytes_read: isize = 0;
		let mut total_bytes_read: isize = 0;

		if iov == 0x0 {
			info!("READV: iov is null");
                	return -EINVAL as isize;		
		}	


		//TODO: spinlock
	
		for i in 0..vlen {
			

			if unsafe { (*(iov as *const iovec).offset(i as isize)).iov_base as usize == 0 && 
			   (*(iov as *const iovec).offset(i as isize)).iov_base as usize != 0 }	{
				info!("READV: element {} of iov is null", i);
				return -EINVAL as isize;
			}


			bytes_read = unsafe { SYS.read(fd, 
					              (*(iov as *const iovec).offset(i as isize)).iov_base, 
					              (*(iov as *const iovec).offset(i as isize)).iov_len) };

			total_bytes_read += bytes_read;	
		}

		total_bytes_read
	
}


#[no_mangle]
pub extern "C" fn sys_readv(fd: i32, iov: usize, vlen: i32) -> isize {
        kernel_function!(__sys_readv(fd, iov, vlen))
}
