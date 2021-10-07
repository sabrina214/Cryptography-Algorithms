class RSA:
  def __init__(self):
    self.n = None
    self.private_key = None
    self.public_key = None

  def get_primes(self, n, order):
    return 564832025563754167280587259313178386020778350817804920704065099304575495039724503624187344166437202923233411620253906005478409511046084001754181991031066080555702138451933263915528206766999518789810513812021761776355509186810891259466586737626850825233063522246756651904286056527518901457671281079931, 707967648968945567316960339042421462324427012654410215247994086702931151017037438716076615467478332465819579985675737312802259043023044729197953438307305585737340703078952140310806700528609903560189850886262110587862292951033818516860622735943009021692312379979914290612511159882217065056471771861487
    
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

  def generate_key_pair(self):
    # generate two large primes(154 digits)
    p, q = self.get_primes(2, 154)
    self.n = p * q

    # Euler totient function
    phi_n = (p-1) * (q-1)

    # find a coprime e to phi_n using euclidean algo
    self.public_key, inv_e = self.coprime(phi_n)

    # generate private key
    self.private_key = inv_e % phi_n

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
