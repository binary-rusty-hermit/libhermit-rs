use super::*;
use crate::arch_prctl::sys_arch_prctl;
use crate::uname::*;

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_STAT: usize = 4;
const SYS_FSTAT: usize = 5;
const SYS_LSEEK: usize = 8;

#[cfg(feature = "newlib")]
const SYS_BRK: usize = 12;

const SYS_EXIT: usize = 60;
const SYS_UNAME: usize = 63;
const SYS_READLINK: usize = 89;
const SYS_GETTIMEOFDAY: usize = 96;
const SYS_ARCH_PRCTL: usize = 158;
const SYS_OPENAT: usize = 257;

#[no_mangle]
pub unsafe extern "C" fn syscall_handler(state: &mut State) {
	match state.rax {
                SYS_READ => {
                        state.rax = sys_read(state.rdi as i32, state.rsi as *mut u8, state.rdx) as usize;
                        },

                SYS_WRITE => {
                        state.rax = sys_write(state.rdi as i32, state.rsi as *const u8, state.rdx) as usize;
                        },

		 SYS_OPEN => {
                        state.rax = sys_open(state.rdi as *const u8, state.rsi as i32, state.rdx as i32) as usize;
                        },

                SYS_CLOSE => {
                        state.rax = sys_close(state.rdi as i32) as usize;
                        },

		SYS_STAT => {
                        state.rax = sys_stat(state.rdi as *const u8, state.rsi) as usize;
                        },

                SYS_FSTAT => {
                        state.rax = sys_fstat(state.rdi as i32, state.rsi) as usize;
                        },

		SYS_LSEEK => {
                        state.rax = sys_lseek(state.rdi as i32, state.rsi as isize, state.rdx as i32) as usize;
                        },

		#[cfg(feature = "newlib")]
                SYS_BRK => {
                        state.rax = tasks::sys_brk(state.rdi);
                        },

		SYS_EXIT => {
                        state.rax = sys_exit(state.rdi as i32);
                        },

		SYS_UNAME => {
                        state.rax = sys_uname(state.rdi as *mut Utsname) as usize;
                },

		SYS_READLINK => {
                        state.rax = sys_readlink(state.rdi as *const u8, state.rsi as *mut u8, state.rdx) as usize;
                        },

		SYS_GETTIMEOFDAY => {
                        state.rax = sys_gettimeofday(state.rdi as *mut timeval, state.rsi as usize) as usize;
                        },

		SYS_ARCH_PRCTL => {
                        state.rax = sys_arch_prctl(state.rdi, state.rsi as *mut usize);
                }

		SYS_OPENAT => {
                        state.rax = sys_openat(state.rdi as i32, state.rsi as *const u8, state.rdx as i32) as usize;
                }

		 _ => panic!("Rax was: {}, Not implemented", state.rax),
        }

}

/*
fn check_state(state: &State) {
        println!("RAX {}\n
                RCX {}\n
                RDX {}\n
                RBX {}\n
                RBP {}\n
                RSI {}\n
                RDI {}\n
                R8 {}\n
                R9 {}\n
                R10 {}\n
                R11 {}\n
                R12 {}\n
                R13 {}\n
                R14 {}\n
                R15 {}", state.rax, state.rcx, state.rdx, state.rbx, state.rbp, state.rsi, state.rdi, state.r8, state.r9, state.r10, state.r11, state.r12, state.r13, state.r14, state.r15);
}
*/


#[repr(C, packed)]
pub struct State {
        /// RAX register
        rax: usize,
        /// RCX register
        rcx: usize,
        /// RDX register
        rdx: usize,
        /// RBX register
        rbx: usize,
        /// RBP register
        rbp: usize,
        /// RSI register
        rsi: usize,
        /// RDI register
        rdi: usize,
        /// R8 register
        r8: usize,
        /// R9 register
        r9: usize,
        /// R10 register
        r10: usize,
        /// R11 register
        r11: usize,
        /// R12 register
        r12: usize,
        /// R13 register
        r13: usize,
        /// R14 register
        r14: usize,
        /// R15 register
        r15: usize,
}



