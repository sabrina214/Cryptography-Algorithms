from aes import AES


# Below is a 128-bit weak key(not potentially weak for AES) use it to see the effect
# key = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

plain_text = 'Life is beautiful'
key ='sidthyantroy@214'

cipher = AES(plain_text, key)

print('ENCRYPTED TEXT:', cipher.encrypt())
print('DECRYPTED TEXT', cipher.decrypt(), '\n')

# print(cipher.multiply_in_GF8(38, 158))
