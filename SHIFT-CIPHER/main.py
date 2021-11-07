from shift_cipher import Shift_cipher
import sys


if len(sys.argv) != 2:
  print('Usage: python main.py <text-file>')
  sys.exit()

with open(sys.argv[1], 'r') as file:
  key = int(input('Enter key or let caesar encrypt it[Press Enter]: ') or 3)

  cipher = Shift_cipher(file, key)
  cipher.encrypt()
  print("DONE ENCRYPTYING. File saved as '{}'".format(cipher.ENCRYPTED_FIL))

  cipher.decrypt()
  print("DONE DECRYPTYING. File saved as '{}'".format(cipher.DECRYPTED_FIL))
