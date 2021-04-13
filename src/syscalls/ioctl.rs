use crate::errno::*;

const TIOCGWINSZ: i32 =  0x00005413;
const TCGETS: i32 =  0x00005401;
const NCCS: usize = 19;

#[repr(C)]
pub struct winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

#[repr(C)]
pub struct termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
}

#[no_mangle]
pub fn sys_ioctl(fd: i32, cmd: i32, arg: usize) -> usize {
        kernel_function!(__sys_ioctl(fd, cmd, arg))
}


fn __sys_ioctl(fd: i32, cmd: i32, arg: usize) -> usize {
        match cmd {
		// Hack to return what linux returns
                TIOCGWINSZ => {
			let res: *mut winsize = arg as *mut winsize;
                    
			unsafe { (*res).ws_row = 24;
				(*res).ws_col = 80;
				(*res).ws_xpixel = 0;
				(*res).ws_ypixel = 0; }
				    
                    	return 0 as usize;
                },

		// This is also a hack
                TCGETS => {
			let res: *mut termios = arg as *mut termios;
                  
			unsafe { (*res).c_iflag = 0x4500;
				(*res).c_oflag = 0x5;
				(*res).c_cflag = 0xbf;
				(*res).c_lflag = 0x8a3b;
				(*res).c_line = 0x0;
				(*res).c_cc[0] = 0x3;
				(*res).c_cc[1] = 0x1c;
				(*res).c_cc[2] = 0x7f;
				(*res).c_cc[3] = 0x15;
				(*res).c_cc[4] = 0x4;
				(*res).c_cc[5] = 0x0;
				(*res).c_cc[6] = 0x1;
				(*res).c_cc[7] = 0x0;
				(*res).c_cc[8] = 0x11;
				(*res).c_cc[9] = 0x13;
				(*res).c_cc[10] = 0x1a;
				(*res).c_cc[11] = 0x0;
				(*res).c_cc[12] = 0x12;
				(*res).c_cc[13] = 0xf;
				(*res).c_cc[14] = 0x17;
				(*res).c_cc[15] = 0x16;
				(*res).c_cc[16] = 0x0;
				(*res).c_cc[17] = 0x0;
				(*res).c_cc[18] = 0x0; }
				    
	   		return 0 as usize;
                },

                _ => {
                        info!("IOCTL: command not implemented: {}", cmd);
			return -ENOSYS as usize;
                }
        }

}



