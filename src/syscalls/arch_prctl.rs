use crate::arch::x86_64::kernel::processor::writefs;
use crate::arch::x86_64::kernel::processor::readfs;

pub const ARCH_SET_GS: usize = 0x1001;
pub const ARCH_SET_FS: usize = 0x1002;
pub const ARCH_GET_FS: usize = 0x1003;
pub const ARCH_GET_GS: usize = 0x1004;



#[no_mangle]
pub fn sys_arch_prctl(code: usize, addr: *mut usize) -> usize {
        kernel_function!(__sys_arch_prctl(code, addr))
}

fn __sys_arch_prctl(code: usize, addr: *mut usize) -> usize {
        match code {
                ARCH_SET_FS => {
                        writefs(addr as usize);

                        if readfs() != addr as usize { return usize::MAX; }
                        else { return 0 as usize; }
                },

                ARCH_GET_FS => {
                        unsafe { *addr = readfs(); }

                        return 0 as usize;
                },

                _ => {
                        panic!("Arch_prctl: Code was: {}, addr was: {}", code, addr as usize);
                }
        }

}

