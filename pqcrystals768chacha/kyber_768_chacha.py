#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
========================================================================
#--- In Cryptography: KEM is used for hybrid encryption in one shot ---#
========================================================================
"""

import sys

try:
    import ctypes,secrets,string,argparse
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("[-] Run: python3 -m pip install -r requirements.txt")
    sys.exit(1)

KYBERLIB = "./kyberlib.so"

#KYBER PARAMETERS
KYBER_K = 3 #we will choose KYBER768 to test
KYBER_N = 256
KYBER_Q = 3329

KYBER_SYMBYTES = 32
KYBER_SSBYTES = 32

KYBER_POLYBYTES = 384
KYBER_POLYVECBYTES = KYBER_K * KYBER_POLYBYTES
KYBER_ETA1 = 2
KYBER_POLYCOMPRESSEDBYTES = 128
KYBER_POLYVECCOMPRESSEDBYTES = KYBER_K * 320

KEYBER_ETA2 = 2
KYBER_INDCPA_MSGBYTES = KYBER_SYMBYTES
KYBER_INDCPA_PUBLICKEYBYTES = KYBER_POLYVECBYTES + KYBER_SYMBYTES
KYBER_INDCPA_SECRETKEYBYTES = KYBER_POLYVECBYTES
KYBER_INDCPA_BYTES = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES

KYBER_PUBLICKEYBYTES = KYBER_INDCPA_PUBLICKEYBYTES
KYBER_SECRETKEYBYTES = KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES
KYBER_CIPHERTEXTBYTES = KYBER_INDCPA_BYTES

CRYPTO_SECRETKEYBYTES = KYBER_SECRETKEYBYTES
CRYPTO_PUBLICKEYBYTES = KYBER_PUBLICKEYBYTES
CRYPTO_CIPHERTEXTBYTES = KYBER_CIPHERTEXTBYTES
CRYPTO_BYTES = KYBER_SSBYTES

class LoadLib(object):
    def __init__(self,lib:str)->None:
        self.__lib = lib

    def loadlib(self)->object:
        klib = ctypes.CDLL(self.__lib)
        return klib

class ChaCha(object):
    def __init__(self,msg:bytes,length:int)->None:
        self.nonce,self.data = self.gen_data(length)
        self.key = KyberKem().gen_shared_secret()
        self.enc = ChaCha20Poly1305(self.key).encrypt(self.nonce,msg,self.data)
        self.dec = ChaCha20Poly1305(self.key).decrypt(self.nonce,self.enc,self.data)

    @classmethod
    def gen_data(cls,length:int)->tuple:
        nonce = secrets.token_bytes(12) #ChaCha requires 12 bytes nonce
        data = "".join([secrets.choice(string.ascii_lowercase+string.ascii_uppercase+
            string.digits+string.punctuation) for _ in range(length)])
        data = data.encode(encoding="utf-8")
        return nonce,data

class KyberKem(object):
    def __init__(self):
        try:
            self.__klib = LoadLib(KYBERLIB).loadlib()
        except OSError as o_err:
            print("[-] Error: {!s}. Try recompile the library (see README.md)".format(o_err))
            sys.exit(1)
    def gen_shared_secret(self:object)->bytes:

        #wrapping all C functions from library, that we need for Key Encapsulation Mechanism
        #We first of all declare all these functions.

        function_gen = self.__klib.pqcrystals_kyber768_ref_keypair
        function_gen.argtypes = [ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8)]
        function_gen.restype = ctypes.c_int
        
        function_randinit = self.__klib.randombytes_init
        function_randinit.argtypes = [ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_int]

        function_encapsule = self.__klib.pqcrystals_kyber768_ref_enc
        function_encapsule.argtypes = [ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8)]
        function_encapsule.restype = ctypes.c_int

        function_decapsule = self.__klib.pqcrystals_kyber768_ref_dec
        function_decapsule.argtypes = [ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8)]
        function_decapsule.restype = ctypes.c_int

        #ctypes initialize C array with 0. We have to randomize the initialization.
        rand_list_seed = [secrets.choice(range(KYBER_N)) for _ in range(48)]
        seed = (ctypes.c_uint8 * 48)(*rand_list_seed)
        entropy_input = (ctypes.c_uint8 * 48)(*range(48))
        personalized = ctypes.cast(ctypes.c_void_p(None),ctypes.POINTER(ctypes.c_uint8))
        
        rand_list_pk = [secrets.choice(range(KYBER_N)) for _ in range(CRYPTO_PUBLICKEYBYTES)]
        pubkey = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)(*rand_list_pk)

        rand_list_sk = [secrets.choice(range(KYBER_N)) for _ in range(CRYPTO_SECRETKEYBYTES)]
        privkey = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)(*rand_list_sk)

        rand_list_ss = [secrets.choice(range(KYBER_N)) for _ in range(CRYPTO_BYTES)]
        shared_secret = (ctypes.c_uint8 * CRYPTO_BYTES)(*rand_list_ss)

        rand_list_ct = [secrets.choice(range(KYBER_N)) for _ in range(CRYPTO_CIPHERTEXTBYTES)]
        ciphertext = (ctypes.c_uint8 * CRYPTO_CIPHERTEXTBYTES)(*rand_list_ct)
        
        function_randinit(seed,personalized,KYBER_N)
        function_gen(pubkey,privkey) #generate a key pair (public key, private key)
        function_encapsule(ciphertext,shared_secret,pubkey)
        result = b"".join([element.to_bytes(1,byteorder="big") for element in shared_secret])
        return result

def main():
    description="A simple Python script to test the CRYSTALS-KYBER CryptoScheme combining with ChaCha"
    epilog="Built by Qu@ntumCyb3rW0lf"
    parser=argparse.ArgumentParser(description=description,epilog=epilog)
    parser.add_argument("-l","--len",action="store",type=int,dest="length",required=True,
            help="Specify a number of bytes to generate randomly associated additional data")
    given_args = parser.parse_args()
    try:
        length = int(given_args.length)
    except ValueError as err:
        print("[-] Invalid input.")
        sys.exit(1)

    msg = str(input("[*] Enter a message to encrypt: "))
    msg = msg.encode(encoding="utf-8")

    chacha_sch = ChaCha(msg,length)
    print("[+] Shared secret: {}".format(chacha_sch.key))
    print("[+] Cipher text: {}".format(chacha_sch.enc))

if __name__ == "__main__":
    main()

        
