#https://github.com/the-javapocalypse/Python-File-Encryptor/blob/master/script.py
#https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
"""
This script is a base code for "protectsong" to encrypting files
using AES-256 in CBC. It is implemented with 
pycryptodomex python library

The program encrypts any files using AES and computes the hash using SHA256.
After the descryption, the hash of the decrypted file is then 
checked with the original file. The key used for AES is a random 256 bits
and stored in a file named "key.key"

change wav_file_in variables with your own .wav file 

Requirements
pybase64==1.0.1
pycryptodomex==3.9.7

If you want to use venv
python3 -m venv wav-security/
source wav-security/bin/activate
pip install pycryptodomex
pip install pybase64
python -m Cryptodome.SelfTest
"""
import os
from pybase64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256

class CBC_Mode:

    def __init__(self, key, hash_val=""):
        self.key = key
        self.hash_val = hash_val

    def get_file_hash(self, file_path):

        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        h = SHA256.new(data=encrypted_data)
        return h.digest()

    def get_data_hash(self, encrypted_data):
        h = SHA256.new(data=encrypted_data)
        return h.digest()

    def encrypt_file(self, file_name):
        """ Encrypts a file using AES (CBC mode) with the
            given key.

            self.key:
                The encryption key - a string that must be
                either 16, 24 or 32 bytes long. Longer keys
                are more secure.

            file_name:
                Name of the plain text input file

            filename_out:
                output file - '<in_filename>'Encrypt.wav.
            """

        with open(file_name, 'rb') as fo:
            data = fo.read()

        self.hash_val = self.get_data_hash(data)

        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        enc_data = cipher.iv + ct_bytes
        with open(file_name[:-4] + "Encrypt" + ".wav", 'wb') as fo:
            fo.write(enc_data)
        #os.remove(file_name)
        return

    def decrypt_file(self, file_name):
        """
        Decrypts a file using AES (CBC mode) with the
        given key.

        file_name:
            Name of the encrypted input file

        filename_out:
            output file - '<in_filename>'Decrypt.wav.
        """

        with open(file_name, 'rb') as fo:
            cipher_data = fo.read()
        iv = cipher_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_data = unpad(cipher.decrypt(cipher_data[AES.block_size:]), AES.block_size)
        with open(file_name[:-11] + "Decrypt" + ".wav", 'wb') as fo:
            fo.write(dec_data)
        #os.remove(file_name)
        return

    def get_all_files():
        """
        Returns list of absolute paths to
        to all the files that end with .wav
        in current directory

        dirs:
            list of absolute paths
        """

        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname[-3:] == "wav"):
                    dirs.append(dirName + "/" + fname)
        return dirs

    def encrypt_all_files(self, dirs):
        """
        Encrypts all files in dirs
        """
        dirs = self.get_all_files()
        for file_name in dirs:
            self.encrypt_data(file_name)
        return

    def decrypt_all_files(dirs):
        """
        Decrypts all files in dirs
        """
        dirs = self.get_all_files()
        for file_name in dirs:
            self.decrypt_data(file_name)
        return

# Files
wav_file_in = "1kHz_44100Hz_16bit_30sec-1Chan.wav"
wav_file_in2 = "1kHz_44100Hz_16bit_30sec-1ChanEncrypt.wav"
wav_file_in3 = "1kHz_44100Hz_16bit_30sec-1ChanDecrypt.wav"
key_file = "keys.key"

# Generate 256 bit key
key = get_random_bytes(32)

# Save the key to a file
with open(key_file, "wb") as file_key_out:
    file_key_out.write(key)

encObj = CBC_Mode(key)

encObj.encrypt_file(wav_file_in)

encObj.decrypt_file(wav_file_in2)



assert encObj.hash_val == encObj.get_file_hash(wav_file_in3), "Hashes do not match"
if encObj.get_file_hash(wav_file_in) == encObj.get_file_hash(wav_file_in3):
    print( "Hashes do match")

#os.remove(wav_file_in)
#os.remove(wav_file_in2)
