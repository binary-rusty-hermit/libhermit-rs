use super::*;

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_STAT: usize = 4;
const SYS_FSTAT: usize = 5;
const SYS_LSEEK: usize = 8;

const SYS_EXIT: usize = 60;
const SYS_UNAME: usize = 63;
const SYS_READLINK: usize = 89;
const SYS_ARCH_PRCTL: usize = 158;

#[no_mangle]
pub unsafe extern "C" fn syscall_handler(state: &mut State) {
	match state.rax {
                SYS_READ => {
                        state.rax = sys_read(state.rdi as i32, state.rsi as *mut u8, state.rdx) as usize;
                        },

                SYS_WRITE => {
                        state.rax = sys_write(state.rdi as i32, state.rsi as *const u8, state.rdx) as usize;
                        },

		 _ => println!("Rax was: {}, Not implemented", state.rax),
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



