class Shift_cipher:
  '''
  Assumes plaintext consisting of only 26 alphabets of English
  whitespaces are ignored, if any
  '''
  def __init__(self, file, key):
    self.key = key
    self.PLAINTEXT_FIL = file
    self.ENCRYPTED_FIL = './most_secure_file_on_planet.txt'
    self.DECRYPTED_FIL = './decrypted_with_key.txt'

  def encrypt(self):
    with open('./most_secure_file_on_planet.txt', 'w') as encrypted_file:
      for line in self.PLAINTEXT_FIL:
        encrypted_line = ''
        for c in line:
          if c.isalpha():
            encrypted_line += chr(((ord(c.upper()) - ord('A') + self.key) % 26) + ord('A'))
        encrypted_file.write(encrypted_line + '\n')

  def decrypt(self):
    with open(self.ENCRYPTED_FIL, 'r') as encrypted_file:
      with open('decrypted_with_key.txt', 'w') as decrypted_file:
        for line in encrypted_file:
          decrypted_line = ''
          for c in line:
            if c.isalpha():
              decrypted_line += chr(((ord(c.upper()) - ord('A') - self.key) % 26) + ord('A'))
          decrypted_file.write(decrypted_line + '\n')