const SYSNAME: &str = "Hemitux\0";
const NODENAME: &str = "hermitux\0";
const RELEASE: &str = "4.9.0-4-amd64\0";
const VERSION: &str = "0.1-may-2018\0";
const MACHINE: &str = "x86_64\0";
const DOMAINNAME: &str = "\0";

#[repr(C)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

#[no_mangle]
pub fn sys_uname(buf: *mut Utsname) -> i32 {
        kernel_function!(__sys_uname(buf))
}

unsafe fn __sys_uname(buf: *mut Utsname) -> i32 {
        // Check for null pointer
        if buf as usize == 0x0 {
                panic!("Null pointer passed in __sys_name");
        }

        // Zero out memory
        let pointer = buf as *mut [u8; 390]; // Convert to pointer to u8 array
        let mut array = *pointer;
        for i in &mut array[..] {
                *i = 0x0;
        }

        (*buf).sysname[0..SYSNAME.len()].copy_from_slice(SYSNAME.as_bytes());
        (*buf).nodename[0..NODENAME.len()].copy_from_slice(NODENAME.as_bytes());
        (*buf).release[0..RELEASE.len()].copy_from_slice(RELEASE.as_bytes());
        (*buf).version[0..VERSION.len()].copy_from_slice(VERSION.as_bytes());
        (*buf).machine[0..MACHINE.len()].copy_from_slice(MACHINE.as_bytes());
        (*buf).domainname[0..DOMAINNAME.len()].copy_from_slice(DOMAINNAME.as_bytes());

        return 0 as i32;
}





