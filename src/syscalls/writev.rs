use crate::errno::*;
use core::slice;
use crate::syscalls::SYS;
use crate::readv::iovec;

fn __sys_writev(fd: i32, iov: usize, vlen: i32) -> isize {
        // iov is the pointer to the first iovec within the array

                let mut bytes_written: isize = 0;
                let mut total_bytes_written: isize = 0;

                if iov == 0x0 {
                        info!("WRITEV: iov is null");
                        return -EINVAL as isize;
                }

                // Make the array
                let array = unsafe { slice::from_raw_parts(iov as *const iovec, vlen as usize) };

                //TODO: spinlock

                for i in 0..vlen {
                        let length: usize = array[i as usize].iov_len;

                        if array[i as usize].iov_base as usize == 0 && length != 0 {
                                info!("WRITEV: element {} of iov is null", i);
                                return -EINVAL as isize;
                        }

                        let base = array[i as usize].iov_base;

                        bytes_written = unsafe { SYS.write(fd, base, length) };

                        total_bytes_written += bytes_written;
                }

                total_bytes_written
        
}


#[no_mangle]
pub extern "C" fn sys_writev(fd: i32, iov: usize, vlen: i32) -> isize {
        kernel_function!(__sys_writev(fd, iov, vlen))
}

