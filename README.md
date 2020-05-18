# defcon2020-quals-supersafecalc-writeup

More detailed writeup inc.

Thanks to @4rbit3r and @Arm1stice for solving this challenge with me!

## Challenge summary
This challenge was a ptrace-jail running a small calculator stub after parsing your math expressions and converting the reverse polish notation to assembly instructions. Then it runs your code in the stub while ptracing it. 

There is a Seccomp filter that outright `SECCOMP_RET_ALLOW`'s certain syscalls and forwards others to the `ptrace`-ing process for verification using `SECCOMP_RET_TRACE`. The ptracing process would check their arguments and allow some system calls a fixed amount of times and others only with constraints on the parameters. E.g. We could only open files as long as the path was the hardcoded result file name. 

## Bugs

### TL;DR
1. SIGFPE from Integer Overflow in `div` operation would cause the binary would cause the return to grab the return address from 8 bytes lower than intended

2. Filling up the stack all the way to be adjacent to the end of the code to cause the return address to be read from the last 8 bytes of the generated assembly.

3. The ptracer will truncate the assembly to the maximum buffer size which allows us to place an immediate right at CODE_END - 8. 

4. Shellcode in Immediates in calculation, return to code but misaligned to execute it.

5. Now we have arbitrary code execution what do we do?

6. Save second thread by `mmap(0x1000000, MAP_SHARED, RWX)` to restore the code segment there.

7. Now we control two threads.

8. Race condition in the ptracer when it checks the file path for open. We have one thread constantly swapping between `real path (7 bytes+\0)` and `///flag\0`.

9. Ptracer will see the correct path, by the time the `open()` system call actually executes the path will be `/flag`. 

10. Read contents, write to results file.

### Getting code execution in the ptracee (Bugs: Incorrect handling of SIGFPE & Truncation of the assembly)
The ptracer had a special case for when the process received a SIGFPE signal. It was intended to make any divisions by zero to just return zero. It looked something like this in the decompiled python: 

```
res = ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
if regs.rbp == 0:
    regs.rax = 0
    fd = os.open('/proc/%d/mem' % pid, os.O_RDWR)
    writen(fd, struct.pack('<Q', regs.rax), regs.rsp - 8)
    os.close(fd)
    regs.rsp -= 8
    regs.rsp += 16
regs.rip = FUNCTIONS + 1024
ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))
```
Here `RBP` was the register the divison operation used for the divisor. If the divisor was zero it would instead push the value zero as the result and jump to the `next_operation` stub. As you can see here, if a division by zero occurs the stack pointer ends up being incremented by 8.

If we can trigger a SIGFPE with `rbp != 0` however, this does not happen. Then our stack ends up misaligned which allows us to incorrectly return to `rsp-8` instead of at the correct place. 

After searching for a while we found way to trigger a SIGFPE without dividing by zero by looking at the specification of the `div` instruction in x86(_64) (see [here](https://c9x.me/x86/html/file_module_x86_id_72.html)).

![](https://raw.githubusercontent.com/Lukas-Dresel/defcon2020-quals-supersafecalc-writeup/master/pic1.png)

Here we can see that there's two ways to trigger what is called a Divide Exception (#DE), either dividing by zero or if the quotient is too large to fit into the designated register. This can happen because `div` divides the register pair `RDX:RAX` by the divisor register and places the result into `RAX` and the remainder in `RDX`. If `RDX:RAX` exceeds the 64bit range in our case (aka `RDX != 0`) and we divide by 1 the result will not fit into `RAX` and an overflow will occur.

The division operation in the binary does not clear `RDX` before dividing and so if we have a way of setting `RDX` to any non-zero value, we can trigger this by simply a `(1/1)` as that will then turn into the operation `(0x20000000000000001/1)` if for example `RDX == 2`.
