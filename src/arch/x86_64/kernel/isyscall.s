.global isyscall
isyscall:
                sub $0x100, %rsp        // Create some room to use, to  not mess up stack
                push %r15
                push %r14
                push %r13
                push %r12
                push %r11               // rflags
                push %r10
                push %r9
                push %r8
                push %rdi
                push %rsi
                push %rbp
                push %rbx
                push %rdx
                push %rcx               // Return address
                push %rax               // First variable to struct
                mov %rsp, %rdi          // Address of struct on stack
                call syscall_handler
                pop %rax
                pop %rcx                // Address in application code
                pop %rdx
                pop %rbx
                pop %rbp
                pop %rsi
                pop %rdi
                pop %r8
                pop %r9
                pop %r10
                pop %r11
                pop %r12
                pop %r13
                pop %r14
                pop %r15
                push %r11
                popfq                   // Restore rflags
                add $0x100, %rsp        // Discard used space on stack
                jmp *%rcx               // Jump back to application code




