class PRESENT:
  def __init__(self, plaintext, key):
    self.plaintext = plaintext
    self.key = key
    self.key_reg = self.str_to_int(self.key)    

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
    self.padding_len = 0
    self.hex_text = '' # contains the 64-bit hex block
    self.encrypted_text = '' # contains the final encrypted text in hexadecimal representation
    self.decrypted_text = '' # contains the final decrypted plaintext in ascii format

  def ascii_to_hex(self, ascii_blk):
    '''
    :ascii_blk : ASCII text of arbitrary length
    return hexadecimal string representation of ascii_blk thus utilizing 2x size of ascii_blk
    eg, ascii_to_hex('Life is beautiful')
    >>> 4C6966652069732062656175746966756C
    '''
    hex_str = ''
    for byte in ascii_blk:
      hex_str += '{:02X}'.format(ord(byte))
    self.hex_text += hex_str
    return hex_str

  def hex_to_ascii(self, hex_blk):
    '''
    :hex_blk : Hexadecimal string representation
    return ascii representation of  thus utilizing 2x size of ascii_blk
    eg, ascii_to_hex('70696E6720706f6E672069732064656164')
    >>> 'ping pong is dead'
    '''
    ascii_str =''
    for i in range(0, len(hex_blk), 2):
      ascii_str += chr(int(hex_blk[i] + hex_blk[i+1], 16))
    # self.ascii_text += ascii_str
    return ascii_str

  def show_block(self, blk_no, hex_blk):
    print('{}{}\n{}{}'.format('\nBLOCK ', blk_no, 'HEX BLOCK: ', hex_blk))

  def round_info(self, round, keyed_state, sub_state=None, perm_state=None):
    if not sub_state:
      sub_state = perm_state = 0
    print('Round {:>2}{:>30X}{:>30X}{:>30X}'.format(round, keyed_state, sub_state, perm_state))

  def show_table_heading(self):
    print('{:>38}{:>30}{:>30}'.format('KEY ADDING', 'SBOX LAYER','PBOX LAYER'))

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
      key_reg ^= (round_counter << 15)
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

  def encrypt(self, verbose=False):
    print('\nENCRYPTING')
    print('PLAINTEXT:', self.plaintext)
    
    blk_offset = 0
    last_blk = False

    while not last_blk:
      blk = self.plaintext[blk_offset : blk_offset + self.BLOCK_SIZE // 8]
      blk_size = len(blk)

      if blk_size < self.BLOCK_SIZE // 8:
        if blk_size == 0: break
        self.padding_len = (self.BLOCK_SIZE // 8) - blk_size
        blk += self.padding_len * 'Z'
        last_blk = True

      hex_blk = self.ascii_to_hex(blk)      
      state = self.str_to_int(blk)

      self.show_block(blk_offset // 8, hex_blk)

      if verbose: self.show_table_heading()
      # encrypting 64-bit block
      for round in range( self.NUM_ROUNDS - 1 ):
        keyed_state = self.add_round_key(state, round)
        sub_state = self.substitute(keyed_state)
        state = self.permute(sub_state)
        if verbose: self.round_info(round, keyed_state, sub_state, state)
      state = self.add_round_key(state, self.NUM_ROUNDS - 1 )  
      if verbose: self.round_info(self.NUM_ROUNDS - 1, state)

      # encrytion of 64-bit block completed

      hex_blk = '{:X}'.format(state)
      self.encrypted_text += hex_blk

      blk_offset += (self.BLOCK_SIZE // 8)
      print('ENCRYPTED BLOCK:', hex_blk)

    return self.encrypted_text

  def decrypt(self, verbose=False):
    print('\nDECRYPTING')

    blk_offset = 0
    last_blk = False

    while not last_blk:
      hex_blk = self.encrypted_text[blk_offset : blk_offset + self.BLOCK_SIZE // 4]
      blk_size = len(hex_blk)

      if blk_size == 0: break

      state = int(hex_blk, 16)

      self.show_block(blk_offset // 4, hex_blk)

      if verbose: self.show_table_heading()
      # decrypting 64-bit block
      for round in range( self.NUM_ROUNDS - 1, 0, -1 ):
        keyed_state = self.add_round_key(state, round)
        perm_state = self.permute(keyed_state, inverse=True)
        state = self.substitute(perm_state, inverse=True)
        if verbose: self.round_info(round, keyed_state, state, perm_state)
      state = self.add_round_key(state, 0)
      if verbose: self.round_info(0, state)
      # decryption of 64-bit block completed

      hex_blk = '{:X}'.format(state)
      
      self.decrypted_text += hex_blk

      blk_offset += (self.BLOCK_SIZE // 4)
      print('DECRYPTED BLOCK:', hex_blk)

    if self.padding_len:
      return self.hex_to_ascii(self.decrypted_text)[:-self.padding_len]
    return self.hex_to_ascii(self.decrypted_text)
