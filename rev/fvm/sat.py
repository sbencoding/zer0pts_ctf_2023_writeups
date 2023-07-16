import math
from numpy import isclose

def try_one(user_bytes, vsum, vprod):
    x = 2 * math.pi * user_bytes[1] / 256
    c1 = (x - math.sin(x)) * user_bytes[0]

    y = 2 * math.pi * user_bytes[3] / 256
    c2 = (1 + math.cos(y)) * math.sin(y) * user_bytes[2]

    return isclose(c1 + c2, vsum) and isclose(c1 * c2, vprod)


# print(try_one([ord('z'), ord('e'), ord('r'), ord('0')], 372.9964794763133637, 33111.1640617887597))
# print(try_one([ord('p'), ord('t'), ord('s'), ord('{')], 286.465637790336417695, 30.3161367243592908393))

valid_chars = '0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ}'
def brute(cur, cprod, csum, arr):
    if cur == 4:
        res = try_one(arr, csum, cprod)
        if res: print(arr)
        return res
    for x in valid_chars:
        arr[cur] = ord(x)
        if brute(cur + 1, cprod, csum, arr): return True

    return False

checksums = [
    6571.66532461872422211,
    290.433155332973123253,
    7342.56848339051141883,
    171.755598661240020897,
    146.329092614405974371,
    98.7941988077649587627,
    234.825392102702531757,
    43.3818296912179302248,
    1743.5926260136494107,
    219.683259194217498353,
    3847.87959086742307546,
    165.254968054548666279,
]

flag_sofar = 'zer0pts{'

for i in range(0, len(checksums), 2):
    cprod = checksums[i]
    csum = checksums[i + 1]
    if not brute(0, cprod, csum, [0, 0, 0, 0]):
        print('<missing>')
