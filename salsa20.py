import struct


class Salsa20(object):
    def __init__(self, key, nonce='\x00' * 8, rounds=12):
        """ key dan nonce keduanya merupakan bytestring.
            key harus tepat berukuran 16-byte (128-bit) atau 32-byte (256-bit).
            nonce harus tepat berukuran 8-byte (64 -bit).
            nilai default nonce adalah null.

            Versi Salsa20 ditentukan oleh masukkan round.
            Secara default round pada Salsa20 berjumlah 20-round.
            Salsa20/12 adalah versi yang dipilih oleh eSTREAM.
            Salsa20/8 adalah versi yang lebih cepat dan masih tergolong aman.
        """
        # inisialisasi round
        self._rounds = rounds

        # inisialisasi mask
        self._mask = 0xffffffff

        # inisialisasi nonce
        if len(nonce) != 8:
            raise Exception('nonce harus tepat berukuran 8-byte')
        self._nonce = list(struct.unpack('<2I', nonce))  # unpack nonce

        # inisialisasi key
        if len(key) not in [16, 32]:
            raise Exception('Key harus tepat berukuran 16-byte atau 32-byte')
        if len(key) == 16:
            self._key = list(struct.unpack('<4I', key))  # unpack key
        elif len(key) == 32:
            self._key = list(struct.unpack('<8I', key))

        # inisialisasi block counter
        self._block_counter = [0, 0]  # block counter diberi nilai awal 0 utk setiap word

        tau = (0x61707865, 0x3120646e, 0x79622d36, 0x6b206574)
        sigma = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

        # proses inisialisasi state
        self._state = [0] * 16
        self._state[6] = self._nonce[0]
        self._state[7] = self._nonce[1]
        
        if len(key) == 16:
            self._state[0] = tau[0]
            self._state[1] = self._key[0]
            self._state[2] = self._key[1]
            self._state[3] = self._key[2]
            self._state[4] = self._key[3]
            self._state[5] = tau[1]
            self._state[10] = tau[2]
            self._state[11] = self._key[0]
            self._state[12] = self._key[1]
            self._state[13] = self._key[2]
            self._state[14] = self._key[3]
            self._state[15] = tau[3]
        elif len(key) == 32:
            self._state[0] = sigma[0]
            self._state[1] = self._key[0]
            self._state[2] = self._key[1]
            self._state[3] = self._key[2]
            self._state[4] = self._key[3]
            self._state[5] = sigma[1]
            self._state[10] = sigma[2]
            self._state[11] = self._key[4]
            self._state[12] = self._key[5]
            self._state[13] = self._key[6]
            self._state[14] = self._key[7]
            self._state[15] = sigma[3]
    
    def _expansion(self):
        # periksa nilai block counter
        if self._block_counter[0] <= ((1 << 32) - 1):  # 4-byte, unsigned integer
            self._block_counter[0] += 1
        else:  # jika terjadi overflow di block_counter[0]
            self._block_counter[1] += 1  # lanjutkan ke block_counter[1]
            # not to exceed 2^70 x 2^64 = 2^134 data size ???
        # perbarui nilai block counter
        self._state[8] = self._block_counter[0]
        self._state[9] = self._block_counter[1]
        # state yang telah diperbaharui diproses oleh fungsi hash Salsa20
        return self._salsa20_hash()

    def encrypt(self, datain):
        """ datain dan dataout merupakan bytestring.
            Jika data yang diberikan ke dalam fungsi ini berbentuk blok-blok (chunks)
            Ukuran blok harus tepat 64-byte, hanya blok terakhir yang boleh kurang dari 64-byte.
        """
        dataout = ''
        while datain:
            stream = self._expansion()
            dataout += self._xor(stream, datain[:64])
            if len(datain) <= 64:
                return dataout
            datain = datain[64:]
    decrypt = encrypt

    def _rotl32(self, a, b):
        return ((a << b) | (a >> (32 - b))) & self._mask

    def _quarterround(self, a, b, c, d):
        b ^= self._rotl32((a + d) & self._mask, 7)
        c ^= self._rotl32((b + a) & self._mask, 9)
        d ^= self._rotl32((c + b) & self._mask, 13)
        a ^= self._rotl32((d + c) & self._mask, 18)
        return a, b, c, d

    def _salsa20_hash(self):  # 64 bytes in
        """ self.state merupakan list yang berisi angka unsigned integer berukuran 4-byte(32-bit).
            output harus dikonversi ke bytestring sebelum return.
        """
        x = self._state[:]  # makes a copy
        for i in range(self._rounds):
            if i % 2 == 0:
                # columnround
                x[0], x[4], x[8], x[12] = self._quarterround(x[0], x[4], x[8], x[12])
                x[5], x[9], x[13], x[1] = self._quarterround(x[5], x[9], x[13], x[1])
                x[10], x[14], x[2], x[6] = self._quarterround(x[10], x[14], x[2], x[6])
                x[15], x[3], x[7], x[11] = self._quarterround(x[15], x[3], x[7], x[11])
            if i % 2 == 1:
                # rowround
                x[0], x[1], x[2], x[3] = self._quarterround(x[0], x[1], x[2], x[3])
                x[5], x[6], x[7], x[4] = self._quarterround(x[5], x[6], x[7], x[4])
                x[10], x[11], x[8], x[9] = self._quarterround(x[10], x[11], x[8], x[9])
                x[15], x[12], x[13], x[14] = self._quarterround(x[15], x[12], x[13], x[14])

        # tambahkan state dengan hasil akhir modifikasi state
        for i in range(16):
            x[i] = (x[i] + self._state[i]) & self._mask

        # transpose hasil akhir dan pack menjadi 16-word
        output = struct.pack('<16I',
                             x[0], x[4], x[8], x[12],
                             x[1], x[5], x[9], x[13],
                             x[2], x[6], x[10], x[14],
                             x[3], x[7], x[11], x[15])
        return output  # keluaran bytestring berukuran 64-byte.

    def _xor(self, stream, din):
        dout = []
        for i in range(len(din)):
            dout.append(chr(ord(stream[i]) ^ ord(din[i])))
        return ''.join(dout)


def test():
    import sys
    import time

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
    test()
