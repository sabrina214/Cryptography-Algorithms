from present import PRESENT
from getpass import getpass
import sys


if __name__ == '__main__':
  plaintext = input("Plaintext(press enter for default text): ") or "Spiderman No way home"
  
  attempts = 3
  # 80-bit key
  # key = "0123456789"
  while attempts:
    key = getpass("Key(You won't be able to see as you type): ")
    if len(key) != 10:
      attempts -= 1
      print('Key length must be 10. Attempts left', attempts, '\n')
    else: break
  if not attempts: sys.exit("Try again with valid key")
  
  cipher = PRESENT(plaintext, key)

  verbose = input('Do you want to see verbose output?[Y/n] ').lower().startswith("y")

  print('\nENCRYPTED TEXT:', cipher.encrypt(verbose))

  attempts = 3
  while attempts:
    key = getpass("Key(Enter key to decrypt): ")
    if len(key) != 10:
      attempts -= 1
      print('Key length must be 10. Attempts left', attempts, '\n')
    elif key != cipher.key:
      attempts -= 1
      print('Key invalid! Attempts left', attempts, '\n')
    else: break

  if not attempts: sys.exit("Try again with valid key")
  
  verbose = input('Do you want to see verbose output?[Y/n] ').lower().startswith("y")

  print('\nDECRYPTED TEXT:', cipher.decrypt(verbose), '\n')
