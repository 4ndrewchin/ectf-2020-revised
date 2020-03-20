from speck import SpeckCipher
import os
import numpy as np
import math
import wave

# my_speck = SpeckCipher(0x993456789ABCDEF00FEDCBA987654321,mode='CBC', key_size=256, block_size=128)

my_speck = SpeckCipher(0x123456789ABCDEF00FEDCBA987654321) 
my_plaintext = 0xCCCCAAAA55553333
speck_ciphertext = my_speck.encrypt(my_plaintext)
speck_plaintext = my_speck.decrypt(speck_ciphertext)
print(hex(my_plaintext))
print(speck_ciphertext)
print(speck_plaintext)
print(hex(speck_plaintext))
