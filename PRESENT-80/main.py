from present import PRESENT


# 80-bit key
key = "0123456789"

cipher = PRESENT(key)
print(cipher.round_keys)