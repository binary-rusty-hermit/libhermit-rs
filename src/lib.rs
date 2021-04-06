// Copyright (c) 2017 Stefan Lankes, RWTH Aachen University
//                    Colin Finck, RWTH Aachen University
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/*
 * First version is derived and adapted for HermitCore from
 * Philipp Oppermann's excellent series of blog posts (http://blog.phil-opp.com/)
 * and Eric Kidd's toy OS (https://github.com/emk/toyos-rs).
 */

#![warn(clippy::all)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::tabs_in_doc_comments)]
#![allow(clippy::toplevel_ref_arg)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::println_empty_string)]
#![allow(clippy::single_match)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::forget_copy)]
#![allow(incomplete_features)]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(const_btree_new)]
#![feature(const_fn)]
#![feature(const_mut_refs)]
#![feature(global_asm)]
#![feature(lang_items)]
#![feature(linkage)]
#![feature(linked_list_cursors)]
#![feature(llvm_asm)]
#![feature(panic_info_message)]
#![feature(specialization)]
#![feature(nonnull_slice_from_raw_parts)]
#![feature(core_intrinsics)]
#![feature(alloc_error_handler)]
#![allow(unused_macros)]
#![no_std]
#![cfg_attr(target_os = "hermit", feature(custom_test_frameworks))]
#![cfg_attr(target_os = "hermit", cfg_attr(test, test_runner(crate::test_runner)))]
#![cfg_attr(
	target_os = "hermit",
	cfg_attr(test, reexport_test_harness_main = "test_main")
)]
#![cfg_attr(target_os = "hermit", cfg_attr(test, no_main))]

#![allow(dead_code)]
#![allow(unused_imports)]
#![feature(asm)]

// EXTERNAL CRATES
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;
#[cfg(target_arch = "x86_64")]
extern crate multiboot;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate num_traits;
extern crate scopeguard;
#[cfg(not(target_os = "hermit"))]
#[macro_use]
extern crate std;
#[cfg(target_arch = "x86_64")]
extern crate x86;

use alloc::alloc::Layout;
use core::alloc::GlobalAlloc;
use core::sync::atomic::{spin_loop_hint, AtomicU32, Ordering};

use arch::percore::*;
use mm::allocator::LockedHeap;

pub use crate::arch::*;
pub use crate::config::*;
pub use crate::syscalls::*;

#[macro_use]
mod macros;

#[macro_use]
mod logging;

mod arch;
mod collections;
mod config;
mod console;
mod drivers;
pub mod environment;
mod errno;
mod kernel_message_buffer;
mod mm;
#[cfg(target_os = "hermit")]
mod runtime_glue;
mod scheduler;
mod synch;
mod syscalls;
mod util;

// Binary application system variables etc.
//use std::env;
//use std::ffi::CString;
use alloc::vec::Vec;
use alloc::string::String;

/* Elf ABI */
const AT_NULL: u64         =  0;
const AT_IGNORE: u64       =  1;
const AT_EXECFD: u64       =  2;
const AT_PHDR: u64         =  3;
const AT_PHENT: u64        =  4;
const AT_PHNUM: u64        =  5;
const AT_PAGESZ: u64       =  6;
const AT_BASE: u64         =  7;
const AT_FLAGS: u64        =  8;
const AT_ENTRY: u64        =  9;
const AT_NOTELF: u64       = 10;
const AT_UID: u64          = 11;
const AT_EUID: u64         = 12;
const AT_GID: u64          = 13;
const AT_EGID: u64         = 14;
const AT_PLATFORM: u64     = 15;
const AT_HWCAP: u64        = 16;
const AT_CLKTCK: u64       = 17;
const AT_DCACHEBSIZE: u64  = 19;
const AT_ICACHEBSIZE: u64  = 20;
const AT_UCACHEBSIZE: u64  = 21;
const AT_SECURE: u64       = 23;
const AT_RANDOM: u64       = 25;
const AT_EXECFN: u64       = 31;
const AT_SYSINFO_EHDR: u64 = 33;
const AT_SYSINFO: u64      = 32;
// End of binary application specific

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
	use core::fmt::Write;
	crate::console::CONSOLE.lock().write_fmt(args).unwrap();
}

#[cfg(test)]
#[cfg(target_os = "hermit")]
#[no_mangle]
extern "C" fn runtime_entry(_argc: i32, _argv: *const *const u8, _env: *const *const u8) -> ! {
	println!("Executing hermit unittests. Any arguments are dropped");
	test_main();
	sys_exit(0);
}

//https://github.com/rust-lang/rust/issues/50297#issuecomment-524180479
#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
	println!("Running {} tests", tests.len());
	for test in tests {
		test();
	}
	sys_exit(0);
}

#[cfg(target_os = "hermit")]
#[test_case]
fn trivial_test() {
	println!("Test test test");
	panic!("Test called");
}

#[cfg(target_os = "hermit")]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Interface to allocate memory from system heap
///
/// # Errors
/// Returning a null pointer indicates that either memory is exhausted or
/// `size` and `align` do not meet this allocator's size or alignment constraints.
///
#[cfg(target_os = "hermit")]
pub fn __sys_malloc(size: usize, align: usize) -> *mut u8 {
	let layout_res = Layout::from_size_align(size, align);
	if layout_res.is_err() || size == 0 {
		warn!(
			"__sys_malloc called with size 0x{:x}, align 0x{:x} is an invalid layout!",
			size, align
		);
		return core::ptr::null::<*mut u8>() as *mut u8;
	}
	let layout = layout_res.unwrap();
	let ptr = unsafe { ALLOCATOR.alloc(layout) };

	trace!(
		"__sys_malloc: allocate memory at 0x{:x} (size 0x{:x}, align 0x{:x})",
		ptr as usize,
		size,
		align
	);

	ptr
}

/// Shrink or grow a block of memory to the given `new_size`. The block is described by the given
/// ptr pointer and layout. If this returns a non-null pointer, then ownership of the memory block
/// referenced by ptr has been transferred to this allocator. The memory may or may not have been
/// deallocated, and should be considered unusable (unless of course it was transferred back to the
/// caller again via the return value of this method). The new memory block is allocated with
/// layout, but with the size updated to new_size.
/// If this method returns null, then ownership of the memory block has not been transferred to this
/// allocator, and the contents of the memory block are unaltered.
///
/// # Safety
/// This function is unsafe because undefined behavior can result if the caller does not ensure all
/// of the following:
/// - `ptr` must be currently allocated via this allocator,
/// - `size` and `align` must be the same layout that was used to allocate that block of memory.
/// ToDO: verify if the same values for size and align always lead to the same layout
///
/// # Errors
/// Returns null if the new layout does not meet the size and alignment constraints of the
/// allocator, or if reallocation otherwise fails.
#[cfg(target_os = "hermit")]
pub unsafe fn __sys_realloc(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8 {
	let layout_res = Layout::from_size_align(size, align);
	if layout_res.is_err() || size == 0 || new_size == 0 {
		warn!(
			"__sys_realloc called with ptr 0x{:x}, size 0x{:x}, align 0x{:x}, new_size 0x{:x} is an invalid layout!",
			ptr as usize, size, align, new_size
		);
		return core::ptr::null::<*mut u8>() as *mut u8;
	}
	let layout = layout_res.unwrap();
	let new_ptr = ALLOCATOR.realloc(ptr, layout, new_size);

	if new_ptr.is_null() {
		debug!(
			"__sys_realloc failed to resize ptr 0x{:x} with size 0x{:x}, align 0x{:x}, new_size 0x{:x} !",
			ptr as usize, size, align, new_size
		);
	} else {
		trace!(
			"__sys_realloc: resized memory at 0x{:x}, new address 0x{:x}",
			ptr as usize,
			new_ptr as usize
		);
	}
	new_ptr
}

/// Interface to deallocate a memory region from the system heap
///
/// # Safety
/// This function is unsafe because undefined behavior can result if the caller does not ensure all of the following:
/// - ptr must denote a block of memory currently allocated via this allocator,
/// - `size` and `align` must be the same values that were used to allocate that block of memory
/// ToDO: verify if the same values for size and align always lead to the same layout
///
/// # Errors
/// May panic if debug assertions are enabled and invalid parameters `size` or `align` where passed.
#[cfg(target_os = "hermit")]
pub unsafe fn __sys_free(ptr: *mut u8, size: usize, align: usize) {
	let layout_res = Layout::from_size_align(size, align);
	if layout_res.is_err() || size == 0 {
		warn!(
			"__sys_free called with size 0x{:x}, align 0x{:x} is an invalid layout!",
			size, align
		);
		debug_assert!(layout_res.is_err(), "__sys_free error: Invalid layout");
		debug_assert_ne!(size, 0, "__sys_free error: size cannot be 0");
	} else {
		trace!(
			"sys_free: deallocate memory at 0x{:x} (size 0x{:x})",
			ptr as usize,
			size
		);
	}
	let layout = layout_res.unwrap();
	ALLOCATOR.dealloc(ptr, layout);
}

#[cfg(target_os = "hermit")]
extern "C" {
	static mut __bss_start: usize;
}

/// Helper function to check if uhyve provide an IP device
#[cfg(feature = "newlib")]
fn has_ipdevice() -> bool {
	arch::x86_64::kernel::has_ipdevice()
}

// Push ELF auxiliary vectors to the stack
#[inline(always)]
fn push_auxv(at_type: u64, at_value: u64) {
        unsafe {
                asm!(
                     "push {0}",
                     "push {1}",
                     in(reg) at_value,
                     in(reg) at_type
                );
        }
}

// Initialise values and load the binary application.
fn init_binary(argc: i32, argv: *const *const u8, environ: *const *const u8) -> () {
	// DEBUG
	println!("Init binary");
	// Get boot info.
	let app_size = environment::get_app_size();
	let app_start = environment::get_app_start();
	let app_entry_point = environment::get_app_entry_point();
	let app_ehdr_phoff = environment::get_app_ehdr_phoff();
	let app_ehdr_phnum = environment::get_app_ehdr_phnum();
	let app_ehdr_phentsize = environment::get_app_ehdr_phentsize();

	let mut auxv_platform = format!("x86_64").as_bytes().to_vec();
	auxv_platform.push(0);
	let auxv_platform_ptr = auxv_platform.as_ptr();

	// DEBUG
	println!("app_size: 0x{:x}\napp_start: 0x{:x}\napp_entry_point: 0x{:x}"
		, app_size, app_start, app_entry_point);
	println!("app_ehdr_phoff: {}\napp_ehdr_phnum: {}\napp_ehdr_phentsize: {}"
		, app_ehdr_phoff, app_ehdr_phnum, app_ehdr_phentsize);
	println!("auxv_platform: {:?}", auxv_platform);

	// Get the number of command line args and env vars
	let libc_argc = argc - 1;

	// Create vector of CString pointers to env vars.
	let mut ptr = environ;
	let mut envc = 0;
	let mut env_vars_ptr: Vec<_> = Vec::new();

	unsafe {
		while *ptr != core::ptr::null() {
			envc += 1;
			ptr = environ.offset(envc);
			env_vars_ptr.push(environ.offset(envc));
			// DEBUG
			println!("envc: {}\nptr: {:?}", envc, *ptr);
		}
	}
	env_vars_ptr.push(core::ptr::null());

	println!("libc_argc: {}\nenvc: {}", libc_argc, envc);
	println!("env_vars_ptr: {:?}", env_vars_ptr);

	// Create vector of CString pointers to argv elements.
	let mut argv_ptr: Vec<_> = Vec::new();

	for i in 0..libc_argc {
		unsafe {
			argv_ptr.push(argv.offset(i as isize));
		}
	}
	argv_ptr.push(core::ptr::null());

	println!("argv_ptr: {:?}", argv_ptr);

	println!("Binary loader");

	/* auxv */
	push_auxv(AT_NULL, 0x0);
	push_auxv(AT_IGNORE, 0x0);
	push_auxv(AT_EXECFD, 0x0);
	push_auxv(AT_PHDR, app_start as u64 + app_ehdr_phoff as u64);
	push_auxv(AT_PHNUM, app_ehdr_phnum as u64);
	push_auxv(AT_PHENT, app_ehdr_phentsize as u64);
	push_auxv(AT_RANDOM, app_start as u64);
	push_auxv(AT_BASE, 0x0);
	push_auxv(AT_SYSINFO_EHDR, 0x0);
	push_auxv(AT_SYSINFO, 0x0);
	push_auxv(AT_PAGESZ, 4096);
	push_auxv(AT_HWCAP, 0x0);
	push_auxv(AT_CLKTCK, 0x64); // mimic Linux
	push_auxv(AT_FLAGS, 0x0);
	push_auxv(AT_ENTRY, app_entry_point as u64);
	push_auxv(AT_UID, 0x0);
	push_auxv(AT_EUID, 0x0);
	push_auxv(AT_GID, 0x0);
	push_auxv(AT_EGID, 0x0);
	push_auxv(AT_SECURE, 0x0);
	push_auxv(AT_SYSINFO, 0x0);
	push_auxv(AT_EXECFN, 0x0);
	push_auxv(AT_DCACHEBSIZE, 0x0);
	push_auxv(AT_ICACHEBSIZE, 0x0);
	push_auxv(AT_UCACHEBSIZE, 0x0);
	push_auxv(AT_NOTELF, 0x0);
	push_auxv(AT_PLATFORM, auxv_platform_ptr as u64);


/*
	// DEBUG
	//loop {}
	// Push env var pointers to the stack in reverse order. Starting with null.
	for env_p in env_vars_ptr.iter().rev() {
		unsafe {
			asm!(
			    "push {0}",
			    in(reg) env_p
			);
		}
	}

	// Push argv pointers to the stack in reverse order. Starting with null.
	for argv_p in argv_ptr.iter().rev() {
		unsafe {
			asm!(
			    "push {0}",
			    in(reg) argv_p
			);
		}
	}
*/


	// Clear value in rdx and jump to entry point.
	unsafe {
		asm!(
		    "xor rdx, rdx",
		    "jmp {0}",
		    in(reg) app_entry_point,
		);
	}
}

/// Entry point of a kernel thread, which initialize the libos
#[cfg(target_os = "hermit")]
extern "C" fn initd(_arg: usize) {
	extern "C" {
		#[cfg(not(test))]
		fn runtime_entry(argc: i32, argv: *const *const u8, env: *const *const u8) -> !;
		#[cfg(feature = "newlib")]
		fn init_lwip();
	}

	// initialize LwIP library for newlib-based applications
	#[cfg(feature = "newlib")]
	unsafe {
		if has_ipdevice() {
			init_lwip();
		}
	}

	if environment::is_uhyve() {
		// Initialize the uhyve-net interface using the IP and gateway addresses specified in hcip, hcmask, hcgateway.
		info!("HermitCore is running on uhyve!");
	} else if !environment::is_single_kernel() {
		// Initialize the mmnif interface using static IPs in the range 192.168.28.x.
		info!("HermitCore is running side-by-side to Linux!");
	} else {
		info!("HermitCore is running on common system!");
	}

	// Initialize PCI Drivers if on x86_64
	#[cfg(target_arch = "x86_64")]
	x86_64::kernel::pci::init_drivers();

	syscalls::init();

	// Get the application arguments and environment variables.
	#[cfg(not(test))]
	let (argc, argv, environ) = syscalls::get_application_parameters();

	// give the IP thread time to initialize the network interface
	core_scheduler().reschedule();

	#[cfg(not(test))]
	unsafe {
		// And finally start the application.
		init_binary(argc, argv, environ)
		//runtime_entry(argc, argv, environ)
	}
	#[cfg(test)]
	test_main();
}

fn synch_all_cores() {
	static CORE_COUNTER: AtomicU32 = AtomicU32::new(0);

	CORE_COUNTER.fetch_add(1, Ordering::SeqCst);

	while CORE_COUNTER.load(Ordering::SeqCst) != get_processor_count() {
		spin_loop_hint();
	}
}

/// Entry Point of HermitCore for the Boot Processor
#[cfg(target_os = "hermit")]
fn boot_processor_main() -> ! {
	// Initialize the kernel and hardware.
	arch::message_output_init();
	logging::init();

	info!("Welcome to HermitCore-rs {}", env!("CARGO_PKG_VERSION"));
	info!("Kernel starts at 0x{:x}", environment::get_base_address());
	info!("BSS starts at 0x{:x}", unsafe {
		&__bss_start as *const usize as usize
	});
	info!(
		"TLS starts at 0x{:x} (size {} Bytes)",
		environment::get_tls_start(),
		environment::get_tls_memsz()
	);

	arch::boot_processor_init();
	scheduler::add_current_core();

	if environment::is_single_kernel() && !environment::is_uhyve() {
		arch::boot_application_processors();
	}

	synch_all_cores();

	// Start the initd task.
	scheduler::PerCoreScheduler::spawn(initd, 0, scheduler::task::NORMAL_PRIO, 0, USER_STACK_SIZE);

	let core_scheduler = core_scheduler();
	// Run the scheduler loop.
	loop {
		core_scheduler.reschedule_and_wait();
	}
}

/// Entry Point of HermitCore for an Application Processor
#[cfg(target_os = "hermit")]
fn application_processor_main() -> ! {
	arch::application_processor_init();
	scheduler::add_current_core();

	info!("Entering idle loop for application processor");

	synch_all_cores();

	let core_scheduler = core_scheduler();
	// Run the scheduler loop.
	loop {
		core_scheduler.reschedule_and_wait();
	}
}
