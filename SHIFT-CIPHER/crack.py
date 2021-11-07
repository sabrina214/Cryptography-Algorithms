import sys

if len(sys.argv) == 2:
  DECRYPTED_FIL = './decrypted_wo_key.txt'
elif len(sys.argv) == 3:
  DECRYPTED_FIL = sys.argv[2]
else:
  print('Usage: python crack.py <file-path> | <output-file>')
  sys.exit()

# probably work of some statisticians established this frequency table,
# here the frequcncy values are ignored and the table is in non-decreasing order of frequencies
frequency_table = ['K', 'Q', 'X', 'J', 'V', 'N', 'B', 'P', 'Y', 'G', 'F', 'W', 'M', 'U', 'C', 'L', 'D', 'R', 'H', 'S', 'N', 'I', 'O', 'A', 'T', 'E']

with open(sys.argv[1], 'r') as doomed_file:
  intercepted_text = doomed_file.readlines()

  count = [0] * 26
  for line in intercepted_text:
    for c in line[:-1]:
      count[ord(c) - ord('A')] += 1
  
  while True:
    most_frequent_char_in_encrypted_txt = chr(count.index(max(count)) + ord('A') + 1)
    most_frequent_char_in_inglis = frequency_table.pop()

    probable_key = (ord(most_frequent_char_in_encrypted_txt) - ord(most_frequent_char_in_inglis) - ord('A')) % 26
    print('\nTrying decrypting with key', probable_key)

    decrypted_text = ''
    for c in intercepted_text[0]:
      decrypted_text += chr(((ord(c) - ord('A') - probable_key) % 26) + ord('A'))  
    print('Decrypted text:', decrypted_text, '\n')

    makes_sense = input('I am not equipped with a dictionary neither I have intellect.\nDoes it make any sense to you?[Y/n]')
    if makes_sense == 'Y' or makes_sense == 'y':
      print('Decrypting the rest with key', probable_key)
      break

  with open(DECRYPTED_FIL, 'w') as f:
    for line in intercepted_text:
      decrypted_line = ''
      for c in line[:-1]:
          decrypted_line += chr(((ord(c.upper()) - ord('A') - probable_key) % 26) + ord('A'))
      f.write(decrypted_line + '\n')
  
  print("Done Decrypting😈. File saved as '{}'".format(DECRYPTED_FIL), '\n')
  