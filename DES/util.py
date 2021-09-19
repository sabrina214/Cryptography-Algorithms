def ascii_to_bin(ascii_str):
    bin_str = ''
    hex_str = ''

    hex_map = {
        '0000': '0', '0001': '1', '0010': '2', '0011': '3',
        '0100': '4', '0101': '5', '0110': '6', '0111': '7',
        '1000': '8', '1001': '9', '1010': 'A', '1011': 'B',
        '1100': 'C', '1101': 'D', '1110': 'E', '1111': 'F',
    }

    n = 0
    for c in ascii_str:
        bin_str += '{:08b}'.format(ord(c))
        # hex_str += hex_map[bin_str[:4]] + hex_map[bin_str[4:]]
        n += 8

    padding = ''
    size = n
    
    k = n % 64
    if k: 
        padding = '0' * ((64 - k))
        size += 64-k
    return bin_str + padding, size


def bin_to_hex(bin_str):
    pass

def hex_to_bin(hex_str):
    pass