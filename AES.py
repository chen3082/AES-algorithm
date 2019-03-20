#### Yuan-Cheng Chen
#### 0031169326
#### version 2.7.10
#### ECE 404 Homework #4


import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption


def getnerate_table():

    #### gernerate table
    AES_modulus = BitVector(bitstring='100011011')
    subBytesTable = []  # for encryption
    invSubBytesTable = []  # for decryption
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))

        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable

def gernerate_invtable():
    invSubBytesTable = []  # for decryption
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return invSubBytesTable


def encription():
    keys = round_keys()
    file = open('encrypted.txt','w')
    subBytesTable = getnerate_table()
    bv = BitVector(filename='message.txt')
    while (bv.more_to_read):
        block = bv.read_bits_from_file(128)
        while (len(block)!=128):
            block.pad_from_right(1)
        statearray = state_array(block)
        statearray = xor(statearray, keys[0])

        ########start 14 round################
        for q in range(14):
            statearray = subs(statearray,subBytesTable)
            statearray = rows(statearray)
            if (q<13):
                statearray = columns(statearray)
            statearray = xor(statearray,keys[q+1])
        for i in range(4):
            for l in range(4):
                file.write(statearray[l][i].get_bitvector_in_hex())

    file.close()

def decryption():
    keys = round_keys()

    file = open('decrypted.txt', 'wb')
    invSubBytesTable = gernerate_invtable()
    #print(invSubBytesTable)
    bv = BitVector(filename='encrypted.txt')
    while (bv.more_to_read):
        block = bv.read_bits_from_file(256)
        #block = BitVector(=block)
        #block = block.get_bitvector_in_hex()
        while (len(block) != 256):
            extra = 128-len(block)
            block.pad_from_right(1)
        block=block.get_bitvector_in_ascii()
        block=BitVector(hexstring=block)
        statearray = state_array(block)
        statearray = xor(statearray, keys[14])

        ########start 14 round################
        for q in range(14):
            statearray = invrows(statearray)
            statearray = invsubs(statearray,invSubBytesTable)
            statearray = xor(statearray, keys[13 - q])
            if q<13:
                statearray = invcolumns(statearray)
        for i in range(4):
            for l in range(4):

                statearray[l][i].write_to_file(file)

    file.close()

def invrows(array):
    new_array = [[0 for i in range(4)] for i in range(4)]
    for j in range(4):
        new_array[0][j] = array[0][j]
    for j in range(4):
        if j<3:
            new_array[3][j] = array[3][j+1]
        else:
            new_array[3][j] = array[3][0]
    for j in range(4):
        if j<2:
            new_array[2][j] = array[2][j+2]
        else:
            new_array[2][j] = array[2][j-2]
    for j in range(4):
        if j<1:
            new_array[1][j] = array[1][j+3]
        else:
            new_array[1][j] = array[1][j-1]
    return new_array

def columns(array):
    AES_modulus = BitVector(bitstring='100011011')
    MUL2 = BitVector(bitstring='00000010')
    MUL3 = BitVector(bitstring='00000011')
    new_array = [[0 for i in range(4)] for i in range(4)]

    for g in range(4):
        new_array[0][g] = array[0][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[1][g].gf_multiply_modular(MUL3, AES_modulus, 8)^array[2][g]^array[3][g]
    for g in range(4):
        new_array[1][g] = array[1][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[2][g].gf_multiply_modular(MUL3,AES_modulus,8) ^ array[3][g] ^ array[0][g]
    for g in range(4):
        new_array[2][g] = array[2][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[3][g].gf_multiply_modular(MUL3,AES_modulus,8) ^ array[0][g] ^ array[1][g]
    for g in range(4):
        new_array[3][g] = array[3][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[0][g].gf_multiply_modular(MUL3,AES_modulus,8) ^ array[1][g] ^ array[2][g]
    return new_array

def invcolumns(array):
    AES_modulus = BitVector(bitstring='100011011')
    MUL2 = BitVector(hexstring='0E')
    MUL3 = BitVector(hexstring='0B')
    MUL4 = BitVector(hexstring='0D')
    MUL5 = BitVector(hexstring='09')
    new_array = [[0 for i in range(4)] for i in range(4)]

    for g in range(4):
        new_array[0][g] = array[0][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[1][g].gf_multiply_modular(MUL3, AES_modulus, 8)^array[2][g].gf_multiply_modular(MUL4, AES_modulus, 8)^array[3][g].gf_multiply_modular(MUL5, AES_modulus, 8)
    for g in range(4):
        new_array[1][g] = array[0][g].gf_multiply_modular(MUL5, AES_modulus, 8)^array[1][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[2][g].gf_multiply_modular(MUL3, AES_modulus, 8)^array[3][g].gf_multiply_modular(MUL4, AES_modulus, 8)
    for g in range(4):
        new_array[2][g] = array[0][g].gf_multiply_modular(MUL4, AES_modulus, 8)^array[1][g].gf_multiply_modular(MUL5, AES_modulus, 8)^array[2][g].gf_multiply_modular(MUL2, AES_modulus, 8)^array[3][g].gf_multiply_modular(MUL3, AES_modulus, 8)
    for g in range(4):
        new_array[3][g] = array[0][g].gf_multiply_modular(MUL3, AES_modulus, 8)^array[1][g].gf_multiply_modular(MUL4, AES_modulus, 8)^array[2][g].gf_multiply_modular(MUL5, AES_modulus, 8)^array[3][g].gf_multiply_modular(MUL2, AES_modulus, 8)

    return new_array




def rows(array):
    new_array = [[0 for i in range(4)] for i in range(4)]
    for j in range(4):
        new_array[0][j] = array[0][j]
    for j in range(4):
        if j<3:
            new_array[1][j] = array[1][j+1]
        else:
            new_array[1][j] = array[1][0]
    for j in range(4):
        if j<2:
            new_array[2][j] = array[2][j+2]
        else:
            new_array[2][j] = array[2][j-2]
    for j in range(4):
        if j<1:
            new_array[3][j] = array[3][j+3]
        else:
            new_array[3][j] = array[3][j-1]

    return new_array


def subs(array,subBytesTable):
    #subBytesTable=getnerate_table()
    #print(subBytesTable)
    for i in range(4):
        for j in range(4):
            [LE, RE] = array[i][j].divide_into_two()
            array[i][j] = BitVector(intVal=subBytesTable[int(LE) * 16 + int(RE)], size=8)
    return array

def invsubs(array,invSubBytesTable):
    for i in range(4):
        for j in range(4):
            [LE, RE] = array[i][j].divide_into_two()
            array[i][j] = BitVector(intVal=invSubBytesTable[int(LE) * 16 + int(RE)], size=8)
    return array


def round_keys():
    key_words = []
    keysize, key_bv = get_key_from_user()
    if keysize == 128:
        key_words = gen_key_schedule_128(key_bv)
    elif keysize == 192:
        key_words = gen_key_schedule_192(key_bv)
    elif keysize == 256:
        key_words = gen_key_schedule_256(key_bv)
    else:
        sys.exit("wrong keysize --- aborting")
    key_schedule = []
    #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        #if word_index % 4 == 0: print("\n")
        #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
        key_schedule.append(keyword_in_ints)
    num_rounds = None
    if keysize == 128: num_rounds = 10
    if keysize == 192: num_rounds = 12
    if keysize == 256: num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +key_words[i*4+3]).get_bitvector_in_hex()
    print("\n\nRound keys in hex (first key for input block):\n")
    #for round_key in round_keys:
        #print(round_key)
    return round_keys

    #################################################################################################

def convert_table(number_list):
    bitnumber=[]

    for i in range(4):
        bitnumber.append(BitVector(intVal=number_list[i]))
    return bitnumber

def xor(a,b):
    # plaintext is a, four words is b
    # a is state_array
    bvb = BitVector(hexstring =b)   # convert into bit
    start = 0
    cut = 8
    for i in range(4):
        for j in range(4):
            a[j][i] ^=  bvb[start:cut]
            start +=8
            cut += 8

    return a





def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def get_key_from_user():
    key = keysize = None
    with open('key.txt','r') as file:
        key = file.read()
    keysize = 256
    key = key.strip()
    key += '0' * (keysize//8 - len(key)) if len(key) < keysize//8 else key[:keysize//8]
    key_bv = BitVector( textstring = key )
    return keysize,key_bv

def state_array(block):
    statearray = [[0 for x in range(4)] for x in range(4)]
    # bv = BitVector(filename='messages.txt')
    # block =bv.read_bits_from_file(128)
    for i in range(4):
        for j in range(4):
            statearray[j][i] = block[32*i + 8*j:32*i + 8*(j+1)]
    #print(statearray)
    return statearray



if __name__ =='__main__':
    encription()
    decryption()