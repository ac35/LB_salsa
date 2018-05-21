"""
    A Python implementation of Salsa20.
    
    
    Copyright (c) 2009 by Larry Bugbee, Kent, WA
    ALL RIGHTS RESERVED.
    
    salsa20.py IS EXPERIMENTAL SOFTWARE FOR EDUCATIONAL
    PURPOSES ONLY.  IT IS MADE AVAILABLE "AS-IS" WITHOUT 
    WARRANTY OR GUARANTEE OF ANY KIND.  USE SIGNIFIES 
    ACCEPTANCE OF ALL RISK.  

    To make your learning and experimentation less cumbersome, 
    salsa20.py is free for any use.      
    
    This implementation is intended for Python 2.x.
    
    Larry Bugbee
    May 2009

    Reduced-Round modifications for 6.857 class made by Kevin King

"""

import struct
    
#-----------------------------------------------------------------------

class Salsa20(object):
    """
        Salsa20 was submitted to eSTREAM, an EU stream cipher
        competition).  Salsa20 was originally defined to be 20
        rounds.  Reduced round versions, Salsa20/8 (8 rounds) and
        Salsa20/12 (12 rounds), were also submitted.  Salsa20/12
        was chosen as one of the winners and 12 rounds was deemed
        the "right blend" of security and efficiency.  The default
        for this class is 20 rounds.

        Besides the encryption function and the decryption
        function being identical, exactly how Salsa20 works is
        very simple.  Salsa20 accepts a key and an iv to set up
        an initial 64-byte state.  For each 64-byte block of
        data, the state gets scrambled and XORed with the previous
        state.  This new state is then XORed with the input data
        to produce the output.  Salsa20's security is achieved via
        this one scrambling operation, repeated n times (rounds).

        Sample usage:

         s20 = Salsa20(key, iv, 12)
         ciphertext = s20.encrypt(message)


        Larry Bugbee
        May 2009
    """

    MAX_BLOCK_VALUE = ((1 << 32) - 1)
    TAU    = ( 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 )
    SIGMA  = ( 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 )
    ROUNDS = 12                         # 8, 12, 20
    
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def __init__(self, key, iv='\x00'*8, rounds=ROUNDS):
        """ Both key and iv are bytestrings.  The key must be exactly
            16 or 32 bytes, 128 or 256 bits respectively.  The iv
            must be exactly 8 bytes (64 bits).

            Setting the key but relying on a default iv value (nulls)
            is dangerous.  Either provide the iv here or explicitly
            call iv_setup() to set the iv.

            Salsa20 exists in three basic versions defined by the
            number of rounds (8, 12, and 20).  20 rounds, Salsa20,
            is the default.  12 rounds, Salsa20/12, is the version
            selected by eSTREAM. The 8 round version, Salsa20/8 is
            faster and remains unbroken, but the lesser rounds
            reduces confidence.  Salsa20/8 should not be used with
            high value assets.
            
            The default number of rounds is 12.

        """
        self.key = key
        
        if len(iv) != 8:
            raise Exception('iv must be 8 bytes')
        # unpack iv
        self.iv = list(struct.unpack('<2I', iv))

        if len(self.key) not in [16, 32]:
            raise Exception('key must be either 16 or 32 bytes')
        # unpack key
        if len(self.key) == 16:
            self.k = list(struct.unpack('<4I', self.key))
        elif len(self.key) == 32:
            self.k = list(struct.unpack('<8I', self.key))
        
        # block-counter words set to 0 each
        self.block_counter = [0, 0]
        self.ROUNDS = rounds

        self.initialize_state()
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _expansion(self):
        # check block counter word
        if self.block_counter[0] <=  self.MAX_BLOCK_VALUE:
            self.block_counter[0] += 1
        else: # if overflow in block_counter[0]
            self.block_counter[1] += 1 # carry to block_counter[1]
            # not to exceed 2^70 x 2^64 = 2^134 data size ??? <<<<

        self.state[8] = self.block_counter[0]
        self.state[9] = self.block_counter[1]
        
        return self._salsa20_scramble()
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def initialize_state(self):
        self.state = [0] * 16

        if len(self.key) == 16:
            self.state[0]  = self.TAU[0]
            self.state[1]  = self.k[0]
            self.state[2]  = self.k[1]
            self.state[3]  = self.k[2]
            self.state[4]  = self.k[3]
            self.state[5]  = self.TAU[1]

            self.state[10] = self.TAU[2]
            self.state[11] = self.k[0]
            self.state[12] = self.k[1]
            self.state[13] = self.k[2]
            self.state[14] = self.k[3]
            self.state[15] = self.TAU[3]

        elif len(self.key) == 32:
            self.state[0]  = self.SIGMA[0]
            self.state[1]  = self.k[0]
            self.state[2]  = self.k[1]
            self.state[3]  = self.k[2]
            self.state[4]  = self.k[3]
            self.state[5]  = self.SIGMA[1]

            self.state[10] = self.SIGMA[2]
            self.state[11] = self.k[4]
            self.state[12] = self.k[5]
            self.state[13] = self.k[6]
            self.state[14] = self.k[7]
            self.state[15] = self.SIGMA[3]
        
        self.state[6] = self.iv[0]
        self.state[7] = self.iv[1]
        
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            
    
    def encrypt(self, datain):
        """ datain and dataout are bytestrings. <---- !!bytestrings!!

            If the data is submitted to this routine in chunks,
            the chunk size MUST be an exact multiple of 64 bytes.
            Only the final chunk may be less than an even multiple.
        """
        dataout = ''
        stream  = ''
        while datain:
            stream = self._expansion();
            dataout += self._xor(stream, datain[:64])
            if len(datain) <= 64:
                return dataout
            datain = datain[64:]
        raise Exception('Huh?')
    decrypt = encrypt

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    
    def _ROL32(self, a,b):
        return ((a << b) | (a >> (32 - b))) & 0xffffffff

    def _salsa20_scramble(self):     # 64 bytes in
        """ self.state and other working strucures are lists of
            4-byte unsigned integers (32 bits).

            output must be converted to bytestring before return.
        """
        x = self.state[:]    # makes a copy
        for i in xrange(self.ROUNDS):
            if i % 2 == 0:
                # columnround
                x[ 4] ^= self._ROL32( (x[ 0]+x[12]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[ 4]+x[ 0]) & 0xffffffff,  9)
                x[12] ^= self._ROL32( (x[ 8]+x[ 4]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[12]+x[ 8]) & 0xffffffff, 18)
                x[ 9] ^= self._ROL32( (x[ 5]+x[ 1]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[ 9]+x[ 5]) & 0xffffffff,  9)
                x[ 1] ^= self._ROL32( (x[13]+x[ 9]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 1]+x[13]) & 0xffffffff, 18)
                x[14] ^= self._ROL32( (x[10]+x[ 6]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[14]+x[10]) & 0xffffffff,  9)
                x[ 6] ^= self._ROL32( (x[ 2]+x[14]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 6]+x[ 2]) & 0xffffffff, 18)
                x[ 3] ^= self._ROL32( (x[15]+x[11]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 3]+x[15]) & 0xffffffff,  9)
                x[11] ^= self._ROL32( (x[ 7]+x[ 3]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[11]+x[ 7]) & 0xffffffff, 18)
            if i % 2 == 1:
                # rowround
                x[ 1] ^= self._ROL32( (x[ 0]+x[ 3]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[ 1]+x[ 0]) & 0xffffffff,  9)
                x[ 3] ^= self._ROL32( (x[ 2]+x[ 1]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[ 3]+x[ 2]) & 0xffffffff, 18)
                x[ 6] ^= self._ROL32( (x[ 5]+x[ 4]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 6]+x[ 5]) & 0xffffffff,  9)
                x[ 4] ^= self._ROL32( (x[ 7]+x[ 6]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 4]+x[ 7]) & 0xffffffff, 18)
                x[11] ^= self._ROL32( (x[10]+x[ 9]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[11]+x[10]) & 0xffffffff,  9)
                x[ 9] ^= self._ROL32( (x[ 8]+x[11]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 9]+x[ 8]) & 0xffffffff, 18)
                x[12] ^= self._ROL32( (x[15]+x[14]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[12]+x[15]) & 0xffffffff,  9)
                x[14] ^= self._ROL32( (x[13]+x[12]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[14]+x[13]) & 0xffffffff, 18)
        # OMIT FINAL XOR of initial round state
        # for i in xrange(16):
            # x[i] = (x[i] + self.state[i]) & 0xffffffff
        output = struct.pack('<16I',
                            x[ 0], x[ 1], x[ 2], x[ 3],
                            x[ 4], x[ 5], x[ 6], x[ 7],
                            x[ 8], x[ 9], x[10], x[11],
                            x[12], x[13], x[14], x[15])
        return output                          # 64 bytes out
   
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def _xor(self, stream, din):
        dout = []
        for i in xrange(len(din)):
            dout.append( chr( ord(stream[i]) ^ ord(din[i]) ) )
        return ''.join(dout)

#-----------------------------------------------------------------------
#-----------------------------------------------------------------------

def test():

    def strnumlist(L):
        return ''.join([chr(x) for x in L])

    def printlong(label, bs, bpl, dent):
        tmpl = '%-' + str(dent) + 's'
        while bs:
            print (tmpl % label)[:dent], bs[:bpl].encode('hex')
            label = ''
            bs = bs[bpl:]


    if 0:
        print '-'*40
        key    = 'qwerty7890123456'
        iv     = 'iv345678'
        data   = 'Kilroy'

        s20 = Salsa20(key, iv)
        ciphertext = s20.encrypt(data)

        printlong('  key:',  key,  64, 14)
        printlong('  iv:',   iv,   64, 14)
        printlong('  data:', data, 64, 14)
        printlong('  ciphertext:', ciphertext, 64, 14)

    if 1:
        import sys, time
        
        key = 'qwerty7890123456'
        # key = 'qwerty7890111111' # wrong key
        iv = 'iv345678'

        input_file = open(sys.argv[1], 'rb')
        input_data = input_file.read()
        input_file.close()
        
        plaintext = input_data
        
        cipher = Salsa20(key, iv)
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
        print tmpl2 % (t1-t0),
        print tmpl3 % (len(plaintext) / ((t1-t0)*1000))
        
    if 0:
        print '-'*40
        '''
                     key = 80000000000000000000000000000000
                      IV = 0000000000000000
           stream[0..63] = 4DFA5E481DA23EA09A31022050859936
                           DA52FCEE218005164F267CB65F5CFD7F
                           2B4F97E0FF16924A52DF269515110A07
                           F9E460BC65EF95DA58F740B7D1DBB0AA
        stream[192..255] = DA9C1581F429E0A00F7D67E23B730676
                           783B262E8EB43A25F55FB90B3E753AEF
                           8C6713EC66C51881111593CCB3E8CB8F
                           8DE124080501EEEB389C4BCB6977CF95
        '''
        key  = ('80000000000000000000000000000000').decode('hex')
        iv   = ('0000000000000000').decode('hex')
        data = ('00'*256).decode('hex')      # 512

        ciphertext = Salsa20(key, iv).encrypt(data)

        printlong('  key:',  key,  64, 14)
        printlong('  iv:',   iv,   64, 14)
        printlong('  data:', data, 64, 14)
        printlong('  ciphertext:', ciphertext, 64, 14)


    if 0:
        print '-'*40
        '''
                     key = 80000000000000000000000000000000
                      IV = 0000000000000000
           stream[0..63] = 4DFA5E481DA23EA09A31022050859936
                           DA52FCEE218005164F267CB65F5CFD7F
                           2B4F97E0FF16924A52DF269515110A07
                           F9E460BC65EF95DA58F740B7D1DBB0AA
        stream[192..255] = DA9C1581F429E0A00F7D67E23B730676
                           783B262E8EB43A25F55FB90B3E753AEF
                           8C6713EC66C51881111593CCB3E8CB8F
                           8DE124080501EEEB389C4BCB6977CF95
        '''
        key  = ('80000000000000000000000000000000').decode('hex')
        iv   = ('0000000000000000').decode('hex')
        data = ('00'*256).decode('hex')      # 512

        s20 = Salsa20(key, iv)
        ciphertext  = s20.encrypt(data[:128])
        ciphertext += s20.encrypt(data[128:])

        printlong('  key:',  key,  64, 14)
        printlong('  iv:',   iv,   64, 14)
        printlong('  data:', data, 64, 14)
        printlong('  ciphertext:', ciphertext, 64, 14)


    if 0:
        print '-'*40
        '''
                     key = 80000000000000000000000000000000
                           00000000000000000000000000000000
                      IV = 0000000000000000
           stream[0..63] = E3BE8FDD8BECA2E3EA8EF9475B29A6E7
                           003951E1097A5C38D23B7A5FAD9F6844
                           B22C97559E2723C7CBBD3FE4FC8D9A07
                           44652A83E72A9C461876AF4D7EF1A117
        stream[192..255] = 57BE81F47B17D9AE7C4FF15429A73E10
                           ACF250ED3A90A93C711308A74C6216A9
                           ED84CD126DA7F28E8ABF8BB63517E1CA
                           98E712F4FB2E1A6AED9FDC73291FAA17
        stream[256..319] = 958211C4BA2EBD5838C635EDB81F513A
                           91A294E194F1C039AEEC657DCE40AA7E
                           7C0AF57CACEFA40C9F14B71A4B3456A6
                           3E162EC7D8D10B8FFB1810D71001B618
        stream[448..511] = 696AFCFD0CDDCC83C7E77F11A649D79A
                           CDC3354E9635FF137E929933A0BD6F53
                           77EFA105A3A4266B7C0D089D08F1E855
                           CC32B15B93784A36E56A76CC64BC8477
              xor-digest = 50EC2485637DB19C6E795E9C73938280
                           6F6DB320FE3D0444D56707D7B456457F
                           3DB3E8D7065AF375A225A70951C8AB74
                           4EC4D595E85225F08E2BC03FE1C42567
        '''
        key  = ('80000000000000000000000000000000' +
                '00000000000000000000000000000000'
               ).decode('hex')
        iv   = ('0000000000000000').decode('hex')
        data = ('00'*64).decode('hex')      # 512

        ciphertext = Salsa20(key, iv).encrypt(data)

        printlong('  key:',  key,  64, 14)
        printlong('  iv:',   iv,   64, 14)
        printlong('  data:', data, 64, 14)
        printlong('  ciphertext:', ciphertext, 64, 14)


    if 0:       # caution!!!  this takes time on large data
        print '-'*40
        print 'timing test'
        import time
        
        key  = ('80000000000000000000000000000000' +
                '00000000000000000000000000000000'
               ).decode('hex')
        iv   = ('0000000000000000').decode('hex')
        datalen = 1024
        data = ('00'*datalen).decode('hex')
        iter = 1244
        
        t0 = time.time()
        for i in xrange(iter):
            s20 = Salsa20(key, iv)
            ciphertext = s20.encrypt(data)
        t1 = time.time()
        
        tmpl1 = '  total time to encrypt %d bytes'
        tmpl2 = 'each over %d iterations: %6.4f secs,'
        tmpl3 = 'or about %dKB per sec'
        print tmpl1 % (datalen),
        print tmpl2 % (iter, t1-t0),
        print tmpl3 % ((datalen*iter) / ((t1-t0)*1000))


    print '-'*40

#-----------------------------------------------------------------------
#-----------------------------------------------------------------------

if __name__ == '__main__':
    test()

#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------

