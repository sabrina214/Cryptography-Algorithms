from rsa import RSA


plain_text = input('Press enter key to encrypt/decrypt default text or supply ur own: ') or "This does make sense, it is simple yet elegant but need to watch out and not mess up the implementation"
print('PLAIN TEXT:', plain_text, '\n')

crypto_system = RSA()
crypto_system.generate_key_pair()

encrypted_text = crypto_system.encrypt(plain_text)
print('ENCRYPTED TEXT:', ''.join(hex(c)[2:] for c in encrypted_text), '\n')

decrypted_text = crypto_system.decrypt(encrypted_text)
print('DECRYPTED TEXT:', decrypted_text, '\n')