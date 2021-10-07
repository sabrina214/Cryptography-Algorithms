import sys, random


class RSA:
  def __init__(self):
    self.n = None
    self.private_key = None
    self.public_key = None

  def miller_rabin_pass(self, a, k, d, n):
    # modular exponentiation
    b = pow(a, d, n)
    # if b == 1: 
    #   +1 or -1 do not certainly assure composite but probably prime but better not conclude so early 
    #   return True 
    for _ in range(k-1):
      if b == n - 1: return True
      b = pow(b, 2, n)
    return b == n - 1

  def miller_rabin(self, n):
    # find the largest value k such that 2**k divides n-1 
    b = n - 1
    k = 0
    while b % 2 == 0:
      b >>= 1
      k += 1
    
    # repeat miller rabin test to reduce the probability error exponentially
    for _ in range(20):
      # select any number a; 1 < a < n
      a = random.randrange(2, n)
      if not self.miller_rabin_pass(a, k, b, n):
        return False
    return True

  def generate_prime(self, nbits):
    while True:
      p = random.getrandbits(nbits)
      # msb is set to ensure that our random number is nbits
      # lsb is set to rule out the even numbers from the test 
      p |= 2 ** nbits | 1
      if self.miller_rabin(p):
        return p
    
  def extended_gcd(self, a, b):
    # r = a - q * b
    # t = t1 - q * t2
    t1, t2 = 0, 1

    while b:
      q = a // b
      a, b = b, a % b

      t = t1 - q * t2
      t1, t2 = t2, t
    return a, t1 + b

  def coprime(self, phi_n):
    for i in range(65537, phi_n):    
      gcd, inv_e = self.extended_gcd(phi_n, i)
      if gcd == 1:
        return i, inv_e

  def generate_key_pair(self, nbits):
    # generate two large primes
    print('Generating Key Pair...')
    
    p = self.generate_prime(nbits)
    q = self.generate_prime(nbits)
    self.n = p * q

    # Euler totient function
    phi_n = (p-1) * (q-1)

    # find a coprime e to phi_n using euclidean algo
    self.public_key, inv_e = self.coprime(phi_n)

    # generate private key
    self.private_key = inv_e % phi_n
    print('Key pair generated successfully\n')

  def encrypt(self, plain_text):
    print('Encryting using (e={}, n={})'.format(self.public_key, self.n), '\n')
    encrypted_bytes = [pow(ord(c), self.public_key, self.n) for c in plain_text]
    return encrypted_bytes

  def decrypt(self, encrypted_bytes):
    print('Decrypting using your private key')
    decrypted_text = ''
    for i in encrypted_bytes:
      decrypted_text += chr(pow(i, self.private_key, self.n))
    return decrypted_text
