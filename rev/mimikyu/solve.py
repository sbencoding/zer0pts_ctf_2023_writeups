from pwn import *
correct = b'\xf4\xc5\x25\xc0\xe4\x0f\x00\x00\x8a\x7e\xf1\x2f\x79\x1b\x00\x00\x40\xab\x56\xb1\x83\x01\x00\x00\xda\xe5\xf5\xfc\xef\x0b\x00\x00\x51\xe2\x86\xcf\x97\x02\x00\x00\xb4\xd4\xc1\xed\xb3\x0e\x00\x00\x08\x3a\xce\x10\xfa\x00\x00\x00\x72\x86\x41\xdd\x2b\x00\x00\x00\x46\xea\x50\x50\xbb\x5e\x00\x00\x86\xcf\x73\x9b\xbf\x05\x00\x00'[16:]

def dfs(sofar, exp, mod, target):
    if len(sofar) == 4:
        res = pow(int(sofar.encode('ascii').hex(), 16), exp, mod)
        if res == target:
            print(sofar[::-1])
            return True
        return False

    for x in range(0x20, 0x7f):
        if dfs(sofar + chr(x), exp, mod, target): return True

    return False

correct_list = []
for i in range(0, len(correct), 8):
    correct_list.append(u64(correct[i:i+8]))

expmod = [
    (0x0000000000008e63, 0x000003866cd71f1b),
    (0x0000000000008249, 0x000010ae9be3fc8f),
    (0x000000000000c6a1, 0x000009d942eff67d),
    (0x0000000000000c6d, 0x00001de2e3aa8bb1),
    (0x000000000000aef5, 0x0000103fc65841f3),
    (0x000000000000d5df, 0x0000011a0970edc9),
    (0x000000000000e68d, 0x00005f8d20bddf39),
    (0x000000000000f3fb, 0x000045b14e11e0ed),
]

for i in range(0, 8):
    res = dfs('', expmod[i][0], expmod[i][1], correct_list[i])
    if not res: print('<missing>')

print('done')
