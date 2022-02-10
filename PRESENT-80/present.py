class PRESENT:
  def __init__(self, plaintext, key):
    self.plaintext = self.str_to_int(plaintext)
    self.key_reg = self.str_to_int(key)
    self.NUM_ROUNDS = 32
    self.BLOCK_SIZE = 64
    self.SBOX = [ 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 ]
    self.SBOX_INV = [self.SBOX.index(i) for i in range(16)]
    self.PBOX = [
       0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
       4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
       8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
      12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
    ]
    self.PBOX_INV = [self.PBOX.index(i) for i in range(64)]
    self.round_keys = self.generate_round_keys(self.key_reg)
    self.encrypted_text = None

  def generate_round_keys(self, key_reg):
    '''
    key schedule
    '''
    round_keys = [0] * self.NUM_ROUNDS
    for round_counter in range( self.NUM_ROUNDS ):
      # round key is taken as leftmost 64 bits of key register
      # i.e. bits 79 to 16 of key_reg
      round_keys[round_counter] = key_reg >> 16

      # update key_reg
      # 1. left-shift key_reg 61 bits
      bits_61 = key_reg >> 19
      key_reg = (key_reg << 61) & 0xffff_ffff_ffff_ffff_ffff
      key_reg |= bits_61

      # 2. leftmost 4 bits of key_reg are passed thru sbox
      rightmost_76_bits = key_reg & 0xffff_ffff_ffff_ffff_fff
      key_reg = (self.SBOX[key_reg >> 76] << 76) | rightmost_76_bits

      # 3. XOR round_counter with bits 19, 18, 17, 16, 15 of key_reg
      key_reg ^= ((round_counter + 1) << 15)
    return round_keys

  def str_to_int(self, word):
    '''
    Return integer value of 64 bit ascii word
    '''
    int_word = 0
    # k = 72
    for byte in word:
      int_word <<= 8
      int_word |= ord(byte)
      # k -= 8
    return int_word
  
  def add_round_key(self, state, round):
    return state ^ self.round_keys[round]

  def substitute(self, state, inverse=False):
    if inverse:
      sbox = self.SBOX_INV
    else:
      sbox = self.SBOX
 
    sboxed_state = 0
    for offset in range( self.BLOCK_SIZE // 4 ):
      sboxed_state |= (sbox[ (state >> (4*offset)) & 0xF ] << (4*offset))
    return sboxed_state

  def permute(self, state, inverse=False):
    if inverse:
      pbox = self.PBOX_INV
    else:
      pbox = self.PBOX

    permuted_state = 0
    for in_bit in range( self.BLOCK_SIZE ):
      permuted_state |= ( ( (state >> in_bit) & 0b1 ) << pbox[in_bit] )
    return permuted_state

  def encrypt(self):
    state = self.plaintext
    for round in range( self.NUM_ROUNDS - 1 ):
      state = self.add_round_key(state, round)
      state = self.substitute(state)
      state = self.permute(state)
    state = self.add_round_key(state, self.NUM_ROUNDS - 1 )  
    self.encrypted_text = state
    return state

  def decrypt(self):
    state = self.encrypted_text

    for round in range( self.NUM_ROUNDS - 1, 0, -1 ):
      state = self.add_round_key(state, round)
      state = self.permute(state, inverse=True)
      state = self.substitute(state, inverse=True)
    state = self.add_round_key(state, 0 )  
    return state
