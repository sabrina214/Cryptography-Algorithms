class PRESENT:
  def __init__(self, key):
    self.key_reg = self.str_to_int(key)
    self.NUM_ROUNDS = 32
    self.SBOX = [
      0xC,
      0x5,
      0x6,
      0xB,
      0x9,
      0x0,
      0xA,
      0xD,
      0x3,
      0xE,
      0xF,
      0x8,
      0x4,
      0x7,
      0x1,
      0x2
    ]
    self.round_keys = self.generate_round_keys(self.key_reg)

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
      key_reg = (self.substitute(self.SBOX, key_reg >> 76) << 76) | rightmost_76_bits

      # 3. XOR round_counter with bits 19, 18, 17, 16, 15 of key_reg
      key_reg ^= (round_counter << 15)
    return round_keys

  def str_to_int(self, key):
    '''
    Return integer representation of key
    '''
    int_key = 0
    k = 72
    for byte in key:
      int_key |= ord(byte) << k
      k -= 8
    return int_key
  
  def substitute(self, sbox, word):
    return sbox[word]