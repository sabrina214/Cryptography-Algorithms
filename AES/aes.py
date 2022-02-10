class AES:
  def __init__(self, plain_text, key):
    self.text = plain_text
    self.hex_text = ''

    self.key = key
    self.AES_BLOCK_SIZE = 16 # in bytes
    self.round_keys = None

    self.encrypted_text = ''
    self.decrypted_text = ''
    self.padding_len = 0

    self.subbytes_sbox = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    self.inv_subbytes_sbox = [
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    self.r_constants = [
      0x01000000, 
      0x02000000, 
      0x04000000,
      0x08000000, 
      0x10000000, 
      0x20000000, 
      0x40000000,
      0x80000000, 
      0x1B000000, 
      0x36000000
    ]

    self.mixbytes_sbox = [
      [0x02, 0x03, 0x01, 0x01],
      [0x01, 0x02, 0x03, 0x01],
      [0x01, 0x01, 0x02, 0x03],
      [0x03, 0x01, 0x01, 0x02]
    ]

    self.inv_mixbytes_sbox = [
      [0x0E, 0x0B, 0x0D, 0x09],
      [0x09, 0x0E, 0x0B, 0x0D],
      [0x0D, 0x09, 0x0E, 0x0B],
      [0x0B, 0x0D, 0x09, 0x0E]
    ]

  def ascii_to_hex(self, ascii_blk):
    '''
    :ascii_blk : ASCII text of arbitrary length
    return hexadecimal string representation of ascii_blk thus utilizing 2x size of ascii_blk
    eg, ascii_to_hex('Life is beautiful')
    >>> 4c6966652069732062656175746966756c
    '''
    hex_str = ''
    for byte in ascii_blk:
      hex_str += '{:02x}'.format(ord(byte))
    self.hex_text += hex_str
    return hex_str

  def hex_to_ascii(self, hex_blk):
    '''
    :hex_blk : Hexadecimal string representation
    return ascii representation of  thus utilizing 2x size of ascii_blk
    eg, ascii_to_hex('70696e6720706f6e672069732064656164')
    >>> 'ping pong is dead'
    '''
    ascii_str =''
    for i in range(0, len(hex_blk), 2):
      ascii_str += chr(int(hex_blk[i] + hex_blk[i+1], 16))
    # self.ascii_text += ascii_str
    return ascii_str

  def blk_to_state(self, blk):
    '''
    :blk : hexadecimal string representing a 128-bit(16 bytes) block
    return 4 x 4 matrix where each cell is consists a byte stored as hexadecimal integer
    eg, blk_to_state('12345678902143658709badcfe')
    >>> [[0x12, 0x90, 0x21, 0x09],
         [0x34, 0xab, 0x43, 0xba],
         [0x56, 0xcd, 0x65, 0xdc],
         [0x78, 0xef, 0x87, 0xfe]]
    '''
    return [[int(blk[(i + 4 * j)] + blk[(i + 4 * j) + 1], 16) for j in range(0, 8, 2)] for i in range(0, 8, 2)]

  def state_to_blk(self, state):
    '''
    :state : 4 x 4 matrix where each cell is consists a byte stored as hexadecimal integer
    return flattened state with each byte represented as hexadecimal string
    eg, state_to_blk(
        [[0x12, 0x90, 0x21, 0x09],
         [0x34, 0xab, 0x43, 0xba],
         [0x56, 0xcd, 0x65, 0xdc],
         [0x78, 0xef, 0x87, 0xfe]]
         )
    >>> '12345678902143658709badcfe'
    '''

    return ''.join(['{:02x}{:02x}{:02x}{:02x}'
    .format(state[0][col], state[1][col], state[2][col], state[3][col]) for col in range(4)])

  # def show_state(self, state):
  #   for word in state:
  #     for byte in word: 
  #       print('{:02x}'.format(byte), end=' ')
  #       # print('{:>4}'.format(byte), end=' ')
  #     print()
  #   print()

  def show_block(self, blk_no, hex_blk, state):
    print('{}{}\n{}{}\n'
    .format('\nBlock ', blk_no, 'Hex Text:  ', hex_blk))

    print('{:>19}{:>38}{:>30}{:>38}'.format('Subbytes', 'ShiftedRows', 'Mixing', 'KeyAdding'))
    print('{}{:>35}'.format('Round  0',self.state_to_blk(state)))

  def round_info(self, Nr, round, sub_state, shifted_state, mixed_state, keyed_state):
    if round == Nr:
      mixed_state = ''
    print('Round {:>2}{:>35}{:>35}{:>35}{:>35}'.format(round, sub_state, shifted_state, mixed_state, keyed_state))

  def get_hex_word(self, word):
    '''
    : word: 4-byte ascii string
    Return equivalent hexadecimal integer
    '''
    hex_word = 0
    k = 24
    for byte in word:
      hex_word |= ord(byte) << k
      k -= 8
    return hex_word

  def create_temp_word(self, word, round):
    '''
    1. rotate word - shift each byte left with wrapping
    2. substitute_word
    3. xor with R constants
    '''
    leftmost_byte = (word >> 24) & 0xff
    rot_word = (word << 8) & 0xff_ff_ff_ff
    rot_word |= leftmost_byte

    sub_word = 0
    for k in [24, 16, 8, 0]:
      byte = (rot_word >> k) & 0xff
      sub_word = sub_word | (self.subbytes_sbox[byte] << k)

    temp_word = sub_word ^ self.r_constants[round-1]
    return temp_word

  def expand_keys(self, Nr, Nw_k ,Nw):
    self.round_keys = [[0x00000000 for word in range(4)] for round in range(Nr+1)]

    # generate pre round key from cipher key
    for i in range(0, len(self.key), 4):
      self.round_keys[0][i // 4] = self.get_hex_word(self.key[i:4+i])

    for round in range(1, Nr+1):
      self.round_keys[round][0] = self.create_temp_word(self.round_keys[round-1][3], round) ^ self.round_keys[round-1][0]

      for word in range(1, 4):
        self.round_keys[round][word] = self.round_keys[round][word-1] ^ self.round_keys[round-1][word]

    print('\nRound Keys')
    for round_no, round in enumerate(self.round_keys):
      print('Round {:>2}:'.format(round_no), end=' ')
      for word in round:
        print('{:08x}'.format(word), end=' ')
      print()

  def add_key(self, state, key_words):
    for col in range(4):
      k = 24
      for row in range(4):
        state[row][col] = ((key_words[col] >> k) & 0xff) ^ state[row][col]
        k -= 8

  def substitute_bytes(self, state, inverse=False):
    if inverse:
      sbox = self.inv_subbytes_sbox
    else:
      sbox = self.subbytes_sbox

    for row in range(4):
      for col in range(4):
        state[row][col] = sbox[state[row][col]]

  def shift_rows(self, state, inverse=False):
    if inverse:
      for i in range(4):
        state[i] = state[i][4-i:] + state[i][:4-i]
    else:
      for i in range(4):
        state[i] = state[i][i:] + state[i][:i]

  def multiply_in_GF8(self, p1, p2):
    # find the highest bit set in p1

    # at each iteration check if msb of p2 is 1 or 0
    #   if 0 then just left shift p2 once
    #   if 1 then left shift once and xor with the modulus( with msb removed )
    # modulus: x^8 + x^4 + x^3 + x + 1 => 100011101(nine bits)
    # modulus in above step is done by removing msb, ie with, 00011101 => 0x1B

    res = 0
    for i in range(8):
      if (p1 >> i) & 1:
        # include only those partial results that are actually multiplied
        res = res ^ p2

      tmp = p2
      p2 <<= 1
      if (tmp >> 7) & 1:
        p2 = (p2 ^ 0x1b) & 0xff # left shifting p2 may have ninth bit set too so we need to be sure that except rightmost 8 bits all bits are 0 by ANDing the xor result with 11111111
    return res

  def mix_columns(self, state, inverse=False):
    mixed_state = [[0 for row in range(4)] for row in range(4)]

    if inverse:
      constant_mat = self.inv_mixbytes_sbox
    else:
      constant_mat = self.mixbytes_sbox

    for row in range(4):
      for col in range(4):
        for k in range(4):
          mixed_state[row][col] ^= self.multiply_in_GF8(constant_mat[row][k], state[k][col])
    return mixed_state

  def encrypt(self):
    '''
    Return encrypted ascii text of arbitrary length by encrypting 128-bit blocks at a time
    padding the last block if needed
    '''
    print('\nENCRYPTING')
    print('PLAINTEXT:', self.text)
    print('CIPHER KEY:', self.key)

    # key expansion
    BYTES_PER_WORD = 4
    WORDS_PER_KEY = len(self.key) // 4
    NUM_ROUNDS = WORDS_PER_KEY + 6
    TOTAL_WORDS = BYTES_PER_WORD * (NUM_ROUNDS + 1)

    self.expand_keys(NUM_ROUNDS, WORDS_PER_KEY, TOTAL_WORDS)

    # process 128 bit blocks at a time
    '''
      1. convert ascii text into hexadecimal plaintext
      2. represent in 4x4 state
      3. pad last block with bogus character, 'Z' here, if required
    '''
    blk_offset = 0
    last_blk = False

    while not last_blk:
      blk = self.text[blk_offset : blk_offset + self.AES_BLOCK_SIZE]
      blk_size = len(blk)

      if blk_size < self.AES_BLOCK_SIZE:
        if blk_size == 0: break
        self.padding_len = self.AES_BLOCK_SIZE - blk_size
        blk += self.padding_len * 'Z'
        last_blk = True

      hex_blk = self.ascii_to_hex(blk)
      state = self.blk_to_state(hex_blk)

      self.add_key(state, self.round_keys[0])

      self.show_block((blk_offset // self.AES_BLOCK_SIZE), hex_blk, state)
      for round in range(1, NUM_ROUNDS + 1):
        self.substitute_bytes(state)
        a = self.state_to_blk(state)
        self.shift_rows(state)
        b = self.state_to_blk(state)

        if round != NUM_ROUNDS:
          state = self.mix_columns(state)
          c = self.state_to_blk(state)
        self.add_key(state, self.round_keys[round])
        d = self.state_to_blk(state)

        self.round_info(NUM_ROUNDS, round, a, b, c, d)

      hex_blk = self.state_to_blk(state)
      self.encrypted_text += hex_blk

      blk_offset += self.AES_BLOCK_SIZE
      print('\nENCRYPTED BLOCK:', hex_blk)
    return self.encrypted_text

  def decrypt(self):
    '''
    Return decrypted ascii text of arbitrary length by decrypting 128-bit blocks at a time
    with the padding removed, if any.
    '''

    print('\nDECRYPTING')

    BYTES_PER_WORD = 4
    WORDS_PER_KEY = len(self.key) // 4
    NUM_ROUNDS = WORDS_PER_KEY + 6
    TOTAL_WORDS = BYTES_PER_WORD * (NUM_ROUNDS + 1)

    blk_offset = 0
    last_blk = False

    while not last_blk:
      hex_blk = self.encrypted_text[blk_offset : blk_offset + (self.AES_BLOCK_SIZE * 2)]
      blk_size = len(hex_blk)

      if blk_size == 0: break

      state = self.blk_to_state(hex_blk)
      self.add_key(state, self.round_keys[NUM_ROUNDS])
      self.show_block((blk_offset // (self.AES_BLOCK_SIZE * 2)), hex_blk, state)

      for round in range(NUM_ROUNDS-1, -1, -1):
        self.shift_rows(state, inverse=True)
        a = self.state_to_blk(state)
        self.substitute_bytes(state, inverse=True)
        b = self.state_to_blk(state)
        self.add_key(state, self.round_keys[round])
        c = self.state_to_blk(state)
        if round != 0:
          state = self.mix_columns(state, inverse=True)
          d = self.state_to_blk(state)

        self.round_info(NUM_ROUNDS, NUM_ROUNDS - round, a, b, c, d)

      hex_blk = self.state_to_blk(state)
      self.decrypted_text += hex_blk

      blk_offset += (self.AES_BLOCK_SIZE * 2)
      print('\nDECRYPTED BLOCK:', hex_blk)

    if self.padding_len:
      return self.hex_to_ascii(self.decrypted_text)[:-self.padding_len]
    return self.hex_to_ascii(self.decrypted_text)
