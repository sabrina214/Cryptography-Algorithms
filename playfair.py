def generate_playfair_key(key):
    letters = [0] * 26
    n = len(key)

    temp = ''
    for i in range(n + 26):
        if i < n:
            temp += key[i].lower()
        else:
            c = chr(i + ord('A') - n)
            if c == 'J':
                temp += chr(i + ord('A') - n + 1)
            else:
                temp += chr(i + ord('A') - n)
    
    playfair = [[0 for i in range(5)] for j in range(5)]
    k = 0
    for i in range(5):
        for j in range(5):
            while letters[ord(temp[k].lower()) - ord('a')] == 1:
                k += 1
            
            playfair[i][j] = temp[k].upper()
            letters[ord(temp[k].lower()) - ord('a')] = 1
            k += 1
    
    print('+-----------+')
    for i in playfair:
        print('| ', end="")
        for j in i:
            print(j, end=' ')
        print('|')
    print('+-----------+')
    
    return playfair


def encipher(plaintext, playfair):
    temp = ''
    n = len(plaintext)
    for i in range(0, n, 2):
        m = plaintext[i]
        n = plaintext[i+1]
        
        if m == n:
            temp += m + 'x' + n
        else:
            temp += m + n

    n = len(temp)
    if n % 2: temp += 'x'

    cipher_text = ''
    pi = pj = qi = qj = 0
    for k in range(0, n, 2):
        p = temp[k]
        q = temp[k+1]
        for i in range(5):
            for j in range(5):
                if p == 'j': p = 'i'
                if q == 'j': q = 'i'
                if playfair[i][j] == p.lower() or playfair[i][j] == p.upper() :
                    pi = i
                    pj = j
                elif playfair[i][j] == q.lower() or playfair[i][j] == q.upper():
                    qi = i
                    qj = j
    

        # playfair rules
        if pi == qi: # lying in same row
            cipher_text += playfair[pi][(pj+1)%5] + playfair[qi][(qj+1)%5]
        elif pj == qj: # lying in same column
            cipher_text += playfair[(pi+1)%5][pj] + playfair[(qi+1)%5][qj]
        else:
            cipher_text += playfair[pi][qj] + playfair[qi][pj]
    
    return cipher_text


def decipher(cipher_text, key):
    n = len(cipher_text)
    temp = ''
    pi = pj = qi = qj = 0
    for k in range(0, n, 2):
        p = cipher_text[k]
        q = cipher_text[k+1]
        for i in range(5):
            for j in range(5):
                if playfair[i][j] == p.lower() or playfair[i][j] == p.upper() :
                    pi = i
                    pj = j
                elif playfair[i][j] == q.lower() or playfair[i][j] == q.upper():
                    qi = i
                    qj = j
    

        # playfair rules
        if pi == qi: # lying in same row
            temp += playfair[pi][(pj+4)%5] + playfair[qi][(qj+4)%5]
        elif pj == qj: # lying in same column
            temp += playfair[(pi+4)%5][pj] + playfair[(qi+4)%5][qj]
        else: # what else can it be :/
            temp += playfair[pi][qj] + playfair[qi][pj]
    
    decrypted_text = temp[i]
    for i in range(1, n-1):
        if not (temp[i] == 'X' and temp[i-1] == temp[i+1]):
            decrypted_text += temp[i]
    
    return decrypted_text + temp[-1]


if __name__ == '__main__':
    plaintext = 'meet me at the school house'.replace(' ', '')
    key = 'sidthyant'

    print('And the key was supposed to be "secret"...') 
    playfair = generate_playfair_key(key)

    print('\nEncrypting...')
    print('Plaintext:', plaintext)
    cipher_text = encipher(plaintext, playfair)
    print('CipherText:', cipher_text)

    print('\nDecrypting...')
    decrypted_text = decipher(cipher_text, playfair)
    print('Decrypted-Text:', decrypted_text)
