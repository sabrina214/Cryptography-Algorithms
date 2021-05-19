def encrypt(plain_text):
    n = len(plain_text)
    cipher_text = ''

    '''
    0 2 4 6 8 10
    1 3 5 7 9
    '''
    
    k = (n // 2) + (n % 2)
    for i in range(n):
        if i < k:
            cipher_text += (plain_text[i*2])
        else:
            cipher_text += (plain_text[i-(k-1)])
            k -= 1
    return cipher_text


def decrypt(cipher_text):
    n = len(cipher_text)
    decrypted_text = ''

    '''
    0 6 1 7 2 8 3 9 4 10 5
    | | | | | | | | |  | |
    0 1 2 3 4 5 6 7 8  9 10
    '''

    k = (n // 2) + (n % 2)
    for i in range(n):
        if i % 2 == 0:
            decrypted_text += (cipher_text[i//2])
        else:
            decrypted_text += (cipher_text[i+(k-1)])
            k -= 1
    return decrypted_text


if __name__ == '__main__':
    plain_text = input('Plaintext: ')

    print('Encrypting...')
    cipher_text = encrypt(plain_text)
    print('Ciphertext:',cipher_text)

    print('\nDecrypting...')
    decrypted_text = decrypt(cipher_text)
    print('Decrypted-text:',decrypted_text)
