from util import ascii_to_bin


class Cipher:
  def __init__(self):
    pass

  def pbox(self, block, perm_table):
    permuted_text = ''
    for in_bit in perm_table:
      permuted_text += block[in_bit - 1]
    return permuted_text

  def xor(self, a, b):
    # print(len(a), len(b))
    xored = ''
    for ai, bi in zip(a, b):
      xored += str(int(ai) ^ int(bi))
    return xored

class DES(Cipher):
  def __init__(self, text, key):
    self.text = text
    self.key = key

    bin_key, key_size = ascii_to_bin(key)
    self.bin_key = bin_key
    self.key_size = key_size

    bin_text, size = ascii_to_bin(text)
    self.bin_text = bin_text
    self.size = size

    self.initial_permutation = [
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7
    ]
    self.final_permutation = [
      40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41,  9, 49, 17, 57, 25
    ]
    self.expansion_permutation = [
      32,  1,  2,  3,  4,  5,
       4,  5,  6,  7,  8,  9,
       8,  9, 10, 11, 12, 13,
      12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25,
      24, 25, 26, 27, 28, 29,
      28, 29, 30, 31, 32,  1
    ]
    self.parity_bit_drop_table = [
      57, 49, 41, 33, 25, 17,  9,  1,
      58, 50, 42, 34, 26, 18, 10,  2,
      59, 51, 43, 35, 27, 19 ,11,  3,
      60, 52, 44, 36, 63, 55, 47, 39,
      31, 23, 15,  7, 62, 54, 46, 38,
      30, 22, 14,  6, 61, 53, 45, 37,
      29, 21, 13,  5, 28, 20, 12,  4,
    ]
    self.compression_permutation = [
      14, 17, 11, 24,  1,  5,  3, 28,
      15,  6, 21, 10, 23, 19, 12,  4,
      26,  8, 16,  7, 27, 20, 13,  2,
      41, 52, 31, 37, 47, 55, 30, 40,
      51, 45, 33 ,48, 44, 49, 39, 56,
      34, 53, 46, 42, 50, 36, 29, 32,
    ]
    self.sbox = [
      [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13, 10,  3,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8 , 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
      ], 
      [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
      ],
      [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
      ],
      [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
      ],
      [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
      ],
      [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
      ],
      [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
      ],
      [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6,  11]
      ]
    ]
    self.des_func_perm = [
      16,  7, 20, 21, 29, 12, 28, 17,
       1, 15, 23, 26,  5, 18, 31, 10,
       2,  8, 24, 14, 32, 27,  3,  9,
      19, 13, 30,  6, 22, 11,  4, 25
    ]
    self.round_keys = self.generate_round_keys()

  def left_shift(self, block, round):
    if round == 0 or round == 1 or round == 8 or round == 15:
      block = block[1:] + block[0]
    else:
      block = block[2:] + block[:2]
    return block

  def generate_round_keys(self):
    # parity bit drop
    round_key = self.pbox(self.bin_key, self.parity_bit_drop_table)
    # print(round_key, len(round_key))

    # split in two 28-bit blocks
    left  = round_key[:28]
    right = round_key[28:]

    keys = [None] * 16
    for round in range(16):
      # print('round:',round)

      left  = self.left_shift(left, round)
      # print(left)

      right = self.left_shift(right, round)
      # print(right)

      combined = left + right
      # print(combined, len(combined))

      keys[round] = self.pbox(combined, self.compression_permutation)
      # print()
    return keys

  def des(self, right, round):
    # DES function

    # 1. expansion p-box
    expanded_right = self.pbox(right, self.expansion_permutation)
    # print(expanded_right, len(expanded_right))

    # 2. whitener
    xored = self.xor(expanded_right, self.round_keys[round])
    # print(xored, len(xored))

    # sboxed_out = [0] * 32
    sboxed_out = ''
    for i in range(8):
      row = 2 * int(xored[i * 6]) + int(xored[(i * 6) + 5])
      col = (8 * int(xored[(i * 6) + 1])) + (4 * int(xored[(i * 6) + 2])) + (2*int(xored[(i * 6) + 3])) + int(xored[(i * 6) + 4])

      substitute_val = self.sbox[i][row][col]

      sboxed_out += str(substitute_val >> 3 & 1)
      sboxed_out += str(substitute_val >> 2 & 1)
      sboxed_out += str(substitute_val >> 1 & 1)
      sboxed_out += str(substitute_val & 1)

    # print(sboxed_out, len(sboxed_out))

    # straight permutation 32-bit
    des_perm_out = self.pbox(sboxed_out, self.des_func_perm)

    return des_perm_out

  def mixer(self, left, right, round):
    # print(self.bin_key, len(self.bin_key))
    xored = self.xor(left, self.des(right, round))
    return xored

  def swap(self, left, right):
    return right, left 

  def encrypt(self):
    permuted_text = ''
    
    encrypted_text = ''
    for i in range(0, self.size, 64):
      # initial permutation
      permuted_text = self.pbox(self.bin_text[i:64+i], self.initial_permutation)
      # print(permuted_text)

      # split 64-bit block into two 32-bit blocks L and R
      left  = permuted_text[:32]
      right = permuted_text[32:]

      for round in range(16):
        # mixer
        mixer_out = self.mixer(left, right, round)
        if round == 15: break

        #swapper
        left, right = swapper_out = self.swap(mixer_out, right)

      #final permutation
      encrypted_text += self.pbox(left + right, self.final_permutation)
      # print(encrypted_text)
    
    # self.bin_text = encrypted_text
    return encrypted_text

  def decrypt(self):
    permuted_text = ''

    decrypted_text = ''

    for i in range(0, self.size, 64):
      # initial permutation
      permuted_text = self.pbox(self.bin_text[i:64+i], self.initial_permutation)

      # split 64-bit block into two 32-bit blocks L and R
      left  = permuted_text[:32]
      right = permuted_text[32:]

      for round in range(16):
        # mixer
        mixer_out = self.mixer(left, right, 15 - round)
        if round == 0: break

        #swapper
        left, right = swapper_out = self.swap(mixer_out, right)

      #final permutation
      decrypted_text += self.pbox(left + right, self.final_permutation)
      # print(decrypted_text)
      
    return decrypted_text


plain_text = input() or '123456789'
key = 'sidthya' # should be 56-bit only

my_cipher = DES(plain_text, key)
print('Binary text before encryption:\n', my_cipher.bin_text)

encrypted_text = my_cipher.encrypt()
print('Binary text after encryption:\n', encrypted_text)

decrypted_text = my_cipher.decrypt()
print('Binary text after decryption:\n', decrypted_text)
