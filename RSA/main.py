from rsa import RSA
import sys


crypto_system = RSA()
print("DISCLAIMER: IF THE PROCESS HALTS LONG ENOUGH FOR YOU TO FINISH SIPPING A HOT TEA THEN JUST DON'T WAIT AND NUKE THE PROCESS AND START AGAIN")

if len(sys.argv) == 2:
  nbits = int(sys.argv[1])
else:
  nbits = int(input('Number of bits for primes(default=512 bits): ')) or 512

crypto_system.generate_key_pair(nbits)

plain_text = input('Press enter key to encrypt/decrypt default text or supply ur own: ') or "This does make sense, it is simple yet elegant but need to watch out and not mess up the implementation"
print('PLAIN TEXT:', plain_text, '\n')

encrypted_text = crypto_system.encrypt(plain_text)
print('ENCRYPTED TEXT:', ''.join(hex(c)[2:] for c in encrypted_text), '\n')

decrypted_text = crypto_system.decrypt(encrypted_text)
print('DECRYPTED TEXT:', decrypted_text, '\n')
