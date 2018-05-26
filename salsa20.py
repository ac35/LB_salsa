import struct


class Salsa20(object):
    MAX_BLOCK_VALUE = ((1 << 32) - 1)  # 4-byte, unsigned integer
    TAU = (0x61707865, 0x3120646e, 0x79622d36, 0x6b206574)
    SIGMA = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    ROUNDS = 12  # 8, 12, 20

    def __init__(self, key, nonce='\x00' * 8, rounds=ROUNDS):
        """ key dan nonce keduanya merupakan bytestring.
            key harus tepat berukuran 16-byte (128-bit) atau 32-byte (256-bit).
            nonce harus tepat berukuran 8-byte (64 -bit).
            nilai default nonce adalah null.

            Versi Salsa20 ditentukan oleh masukkan round.
            Secara default round pada Salsa20 berjumlah 20-round.
            Salsa20/12 adalah versi yang dipilih oleh eSTREAM.
            Salsa20/8 adalah versi yang lebih cepat dan masih tergolong aman.
        """
        # inisialisasi nonce
        if len(nonce) != 8:
            raise Exception('nonce harus tepat berukuran 8-byte')
        self.nonce = list(struct.unpack('<2I', nonce))  # unpack nonce

        # inisialisasi key
        self.key = key
        if len(self.key) not in [16, 32]:
            raise Exception('Key harus tepat berukuran 16-byte atau 32-byte')
        if len(self.key) == 16:
            self.k = list(struct.unpack('<4I', self.key))  # unpack key
        elif len(self.key) == 32:
            self.k = list(struct.unpack('<8I', self.key))

        # inisialisasi block counter
        self.block_counter = [0, 0]  # block counter diberi nilai awal 0 utk setiap word
        self.ROUNDS = rounds
        
        # proses inisialisasi state
        self.state = [0] * 16
        self.state[6] = self.nonce[0]
        self.state[7] = self.nonce[1]
        
        if len(self.key) == 16:
            self.state[0] = self.TAU[0]
            self.state[1] = self.k[0]
            self.state[2] = self.k[1]
            self.state[3] = self.k[2]
            self.state[4] = self.k[3]
            self.state[5] = self.TAU[1]
            self.state[10] = self.TAU[2]
            self.state[11] = self.k[0]
            self.state[12] = self.k[1]
            self.state[13] = self.k[2]
            self.state[14] = self.k[3]
            self.state[15] = self.TAU[3]
        elif len(self.key) == 32:
            self.state[0] = self.SIGMA[0]
            self.state[1] = self.k[0]
            self.state[2] = self.k[1]
            self.state[3] = self.k[2]
            self.state[4] = self.k[3]
            self.state[5] = self.SIGMA[1]
            self.state[10] = self.SIGMA[2]
            self.state[11] = self.k[4]
            self.state[12] = self.k[5]
            self.state[13] = self.k[6]
            self.state[14] = self.k[7]
            self.state[15] = self.SIGMA[3]
    
    def expansion(self):
        # periksa nilai block counter
        if self.block_counter[0] <= self.MAX_BLOCK_VALUE:
            self.block_counter[0] += 1
        else:  # jika terjadi overflow di block_counter[0]
            self.block_counter[1] += 1  # lanjutkan ke block_counter[1]
            # not to exceed 2^70 x 2^64 = 2^134 data size ???
        # perbarui nilai block counter
        self.state[8] = self.block_counter[0]
        self.state[9] = self.block_counter[1]
        # state yang telah diperbaharui diproses oleh fungsi hash Salsa20
        return self.salsa20_hash()

    def encrypt(self, datain):
        """ datain dan dataout merupakan bytestring.
            Jika data yang diberikan ke dalam fungsi ini berbentuk blok-blok (chunks)
            Ukuran blok harus tepat 64-byte, hanya blok terakhir yang boleh kurang dari 64-byte.
        """
        dataout = ''
        while datain:
            stream = self.expansion()
            dataout += self.xor(stream, datain[:64])
            if len(datain) <= 64:
                return dataout
            datain = datain[64:]
    decrypt = encrypt

    @staticmethod
    def rotl32(a, b):
        return ((a << b) | (a >> (32 - b))) & 0xffffffff

    def salsa20_hash(self):  # 64 bytes in
        """ self.state merupakan list yang berisi angka unsigned integer berukuran 4-byte(32-bit).
            output harus dikonversi ke bytestring sebelum return.
        """
        x = self.state[:]  # makes a copy
        for i in range(self.ROUNDS):
            if i % 2 == 0:
                # columnround
                x[4] ^= self.rotl32((x[0] + x[12]) & 0xffffffff, 7)
                x[8] ^= self.rotl32((x[4] + x[0]) & 0xffffffff, 9)
                x[12] ^= self.rotl32((x[8] + x[4]) & 0xffffffff, 13)
                x[0] ^= self.rotl32((x[12] + x[8]) & 0xffffffff, 18)
                x[9] ^= self.rotl32((x[5] + x[1]) & 0xffffffff, 7)
                x[13] ^= self.rotl32((x[9] + x[5]) & 0xffffffff, 9)
                x[1] ^= self.rotl32((x[13] + x[9]) & 0xffffffff, 13)
                x[5] ^= self.rotl32((x[1] + x[13]) & 0xffffffff, 18)
                x[14] ^= self.rotl32((x[10] + x[6]) & 0xffffffff, 7)
                x[2] ^= self.rotl32((x[14] + x[10]) & 0xffffffff, 9)
                x[6] ^= self.rotl32((x[2] + x[14]) & 0xffffffff, 13)
                x[10] ^= self.rotl32((x[6] + x[2]) & 0xffffffff, 18)
                x[3] ^= self.rotl32((x[15] + x[11]) & 0xffffffff, 7)
                x[7] ^= self.rotl32((x[3] + x[15]) & 0xffffffff, 9)
                x[11] ^= self.rotl32((x[7] + x[3]) & 0xffffffff, 13)
                x[15] ^= self.rotl32((x[11] + x[7]) & 0xffffffff, 18)
            if i % 2 == 1:
                # rowround
                x[1] ^= self.rotl32((x[0] + x[3]) & 0xffffffff, 7)
                x[2] ^= self.rotl32((x[1] + x[0]) & 0xffffffff, 9)
                x[3] ^= self.rotl32((x[2] + x[1]) & 0xffffffff, 13)
                x[0] ^= self.rotl32((x[3] + x[2]) & 0xffffffff, 18)
                x[6] ^= self.rotl32((x[5] + x[4]) & 0xffffffff, 7)
                x[7] ^= self.rotl32((x[6] + x[5]) & 0xffffffff, 9)
                x[4] ^= self.rotl32((x[7] + x[6]) & 0xffffffff, 13)
                x[5] ^= self.rotl32((x[4] + x[7]) & 0xffffffff, 18)
                x[11] ^= self.rotl32((x[10] + x[9]) & 0xffffffff, 7)
                x[8] ^= self.rotl32((x[11] + x[10]) & 0xffffffff, 9)
                x[9] ^= self.rotl32((x[8] + x[11]) & 0xffffffff, 13)
                x[10] ^= self.rotl32((x[9] + x[8]) & 0xffffffff, 18)
                x[12] ^= self.rotl32((x[15] + x[14]) & 0xffffffff, 7)
                x[13] ^= self.rotl32((x[12] + x[15]) & 0xffffffff, 9)
                x[14] ^= self.rotl32((x[13] + x[12]) & 0xffffffff, 13)
                x[15] ^= self.rotl32((x[14] + x[13]) & 0xffffffff, 18)
            # proses transpose ditiadakan, lanjut ke round berikutnya.

        # tambahkan state dengan hasil akhir modifikasi state
        for i in range(16):
            x[i] = (x[i] + self.state[i]) & 0xffffffff
        # pack output
        output = struct.pack('<16I',
                             x[0], x[1], x[2], x[3],
                             x[4], x[5], x[6], x[7],
                             x[8], x[9], x[10], x[11],
                             x[12], x[13], x[14], x[15])
        return output  # keluaran bytestring berukuran 64-byte.

    @staticmethod
    def xor(stream, din):
        dout = []
        for i in xrange(len(din)):
            dout.append(chr(ord(stream[i]) ^ ord(din[i])))
        return ''.join(dout)


def test():
    import sys
    import time

    key = 'qwerty7890123456'
    # wrong_key = 'qwerty7890111111'
    nonce = 'nonce345678'

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
    test()
