#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Implementing One-Time-Pad.
"""

import binascii,argparse,sys,time
import secrets,string
from concurrent import futures

def gen_pass(length:int)->str:
	return "".join(secrets.choice(string.ascii_lowercase+\
		string.ascii_uppercase+string.digits+string.punctuation)\
			for _ in range(length))

def gen_key(password:str)->int:
	password = binascii.hexlify(password.encode("utf-8"))
	key = int(password,16)
	return key

def enc(plain_text:str,key:int)->int:
	plain_text = binascii.hexlify(plain_text.encode("utf-8"))
	cipher_text = int(plain_text,16)^key
	return cipher_text

def dec(cipher_text:int,key:int)->str:
	plain_text = format(cipher_text^key,"x")
	padded = ("0"*(len(plain_text)%2))+plain_text
	plain_text = binascii.unhexlify(padded)
	return plain_text.decode()

def main():
	description="Implementing OTP Encryption"
	epilog="Built by Qu@ntumCyb3rW01f"
	parser=argparse.ArgumentParser(description=description,epilog=epilog)
	parser.add_argument("--msg","-m",action="store",dest="msg",type=str,\
		required=True,help="Specify message using quote \"\"")
	parser.add_argument("--wrk","-w",action="store",dest="workers",type=int,\
		default=4,help="Specify number of maximal workers")
	given_args = parser.parse_args()
	try:
		msg = str(given_args.msg)
		workers = int(given_args.workers)
	except ValueError as val_err:
		print("[-] Error: {}".format(str(val_err)))
		sys.exit(1)
	length = len(msg)
	pwd = gen_pass(length)
	priv_key = gen_key(pwd)
	try:
		with futures.ThreadPoolExecutor(max_workers=workers) as _exec:
			exec = _exec.submit(enc,msg,priv_key)
			cipher_text = exec.result()
			print(cipher_text)
	except KeyboardInterrupt:
		print("\n[!] Program is shutting down...")
		time.sleep(1)
		sys.exit(1)
	if(dec(cipher_text,priv_key)==msg):
		print("[+] Correctness of Implementing: Checked!")

if __name__ == "__main__":
	main()
