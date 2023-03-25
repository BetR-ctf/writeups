from pwn import *
import time


def xorshift128(t):
    x = t
    y = 362436069
    z = 521288629
    w = 88675123

    while True:
        t = x ^ ((x << 11) & 0xFFFFFFFF)
        x = y
        y = z
        z = w
        w = w ^ (w >> 19) ^ t ^ (t >> 8)
        yield w


def send_data(data):
    r = remote("counting.insomnihack.ch", 256)
    r.recvuntil(b"Enter your choice. ")
    r.sendline("1".encode('utf-8'))
    t = int(time.time())
    global random_var_for_nonce
    random_var_for_nonce = xorshift128(t)
    r.recvline()
    r.sendline(data.encode('utf-8'))
    result = r.recvline().decode('utf-8').split(" ")[-1].strip()

    r.close()
    return result


def get_admin_message():
    r = remote("counting.insomnihack.ch", 256)
    r.recvuntil(b"Enter your choice. ")
    r.sendline("2".encode('utf-8'))
    result = r.recvline().decode('utf-8').split(" ")[-1].strip()
    r.close()
    return result


def get_nonce(s: str):
    return s[:24]


test_message = "00000000000000000000000000000000000000000000"  # same length as admin
solved = False
while not solved:
    test_encrypted = send_data(test_message)
    admin_encrypted = get_admin_message()
    test_encrypted_raw = test_encrypted[24:24 + 88]
    if get_nonce(test_encrypted) == get_nonce(admin_encrypted):
        text_enc = test_encrypted[24:24 + 88]
        admin_enc = admin_encrypted[24:24 + 88]
        a = test_message.encode('utf-8').hex().upper()
        print("flag : ", bytes.fromhex(hex(int(text_enc, 16) ^ int(admin_enc, 16) ^ int(a, 16))[2:]))
        solved = True
