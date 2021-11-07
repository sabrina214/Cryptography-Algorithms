import random, json


# Diffie-Hellman Key Exchange protocol

# setting up the subgroup

# choose a 256-bit prime number, q, i.e., 2^255 < q < 2^256
# choose a prime p such that p = Nq + 1
# choose N from a random a suitable range
# since p should be odd, it implies N should be even
# we want p to be at least 2048 bits, so N should be of 2048 - 256 bits

def small_primes(n):
  '''
  Returns list of primes less than n
  '''

  # start by considering all numbers as primes
  # and omitting 0 and 1 from consideration
  p_nums = [True] * (n-1)

  i = 2
  while i ** 2 <= n:
    while not p_nums[i-2]:
      # loop until u find a prime
      i += 1
    # i is prime

    # all the multiples of i will be composite
    for j in range(2 * i, ((n + i) // i) * i, i):
      p_nums[j-2] = False

    i += 1
    
  # extract and return all the primes
  return [k for k in range(n-1) if p_nums[k-2]]


def miller_rabin_pass(a, k, d, n):
    b = pow(a, d, n)
    for _ in range(k-1):
      if b == n - 1: return True
      b = pow(b, 2, n)
    return b == n - 1


def miller_rabin(n):
    # find the largest value k such that 2**k divides n-1 
    b = n - 1
    k = 0
    while b % 2 == 0:
      b >>= 1
      k += 1
    
    # repeat miller rabin test to reduce the probability of error
    for _ in range(20):
      # select any number a; 1 < a < n
      a = random.randrange(2, n)
      if not miller_rabin_pass(a, k, b, n):
        return False
    return True


def is_prime(n):
  for p in small_primes(1000):
    if n % p == 0:
      if p == n: return p
  return miller_rabin(n)


def generate_prime(nbits=256):
  while True:
    n = random.getrandbits(nbits)
    # ensure that the random number we generate
    # has nbits and it is odd.
    n |= 2 ** (nbits-1) | 1
    if is_prime(n):
      return n


if __name__ == '__main__':
  NO_OF_BITS = 2048


  with open('dhke_parameters.json', 'w') as dhke_parameters_file:  
    print('[INFO] Generating Diffie-Hellman key exchange public parameters')
    q = generate_prime(nbits=256)
    
    remaining_bits = NO_OF_BITS - 256
    i = 1
    # choose some random n and then find some p,such
    # that p = nq + 1 is prime
    while True:
      # print('-', end='\r')
      n = random.getrandbits(remaining_bits)
      n |= 2 ** (remaining_bits)
      n =  (n >> 1) << 1 # n can be only even 
      p = n * q + 1
      if miller_rabin(p):
        break
      # print('Pass', i)
      i += 1
      # print('|', end='\r')
    print('[INFO] Successfully generated 2048-bit prime modulus')

    # find a primitive element g, i.e., generator of
    # the muliplicative group of p. A generator g is
    # the element of Z*p such that g generates all the
    # elements of the group: {1,...,p-1} or in other words

    # find an element of order q
    while True:
      a = random.randint(2, p - 1)
      g = pow(a, n, p)
      if g != 1 and pow(g, q, p) == 1:
        break
    print('[INFO] Found a primitive element for muliplicative group of p')
    dhke_parameters = {'p': p, 'q': q, 'g': g}
    json.dump(dhke_parameters, dhke_parameters_file, indent=2)
    print('[INFO] DHKE parameters written to ./public/dhke_parameters.json')

    