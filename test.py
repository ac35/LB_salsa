from salsa20 import *
import sys
import time


def main():
    key = 'qwerty7890123456'
    # wrong_key = 'qwerty7890111111'
    nonce = '12345678'

    input_file = open(sys.argv[1], 'rb')
    input_data = input_file.read()
    input_file.close()

    plaintext = input_data

    cipher = Salsa20(key, nonce)
    t0 = time.time()
    ciphertext = cipher.encrypt(plaintext)
    t1 = time.time()

    tmpl1 = '  total time to encrypt %d bytes'
    tmpl2 = ': %6.4f secs,'
    tmpl3 = 'or about %dKB per sec'

    output_file = open(sys.argv[2], 'wb')
    output_file.write(ciphertext)
    output_file.close()
    print tmpl1 % (len(plaintext)),
    print tmpl2 % (t1 - t0),
    print tmpl3 % (len(plaintext) / ((t1 - t0) * 1000))


if __name__ == '__main__':
    main()
