#!/usr/bin/env python3
# -*- coding: utf8 -*-

import secrets,argparse,sys,random,time
from datetime import datetime
from concurrent import futures

MAX_WORKERS = 5


class GenRSA():

	def __init__(self:object,bits_length:int,sec_param:int)->None:
		self.bits_length = bits_length
		self.sec_param = sec_param


	def test_primality(self:object,candidate:int)->bool:
		"""
		Test if a number is prime.
		@candidate -- the number to test
		@self.sec_param -- the number of rounds for testing
		"""
		if candidate == 2 or candidate == 3:
			return True
		if candidate <= 1 or candidate%2 == 0:
			return False
		exponent,odd_part=0,candidate-1
		while odd_part&1 == 0:
			exponent += 1
			odd_part >>= 1

		#running sec_param numbers of rounds
		for _ in range(self.sec_param):
			rand_num = random.SystemRandom().randrange(2,candidate-1)
			test_num = pow(rand_num,odd_part,candidate)
			if test_num != 1 and test_num != candidate-1:
				ind_exp = 1
				while ind_exp < exponent and test_num != candidate-1:
					test_num = pow(test_num,2,candidate)
					if test_num == 1:
						return False
					ind_exp += 1
				if test_num != candidate-1:
					return False
		return True

	def gen_primes(self:object)->int:
		"""
		Generate at first an odd integer randomly
		"""
		candidate = secrets.randbits(self.bits_length)
		# n | 1 = n + 1 if n is even and n | 1 = n if n is odd
		candidate |= (1 << self.bits_length-1) | 1
		#keep testing primality
		while not self.test_primality(candidate):
			candidate = self.gen_primes()
		return candidate

	def run(self)->None:
		first_prime = self.gen_primes()
		second_prime = self.gen_primes()
		modulus = first_prime*second_prime
		print("[+] N = {}".format(modulus))
		print("[+] p = {}".format(first_prime))
		print("[+] q = {}".format(second_prime))

def main():
	description="Implementing GenRSA(1^n)"
	epilog="Built by Qu@ntumCyb3rW01f"
	parser=argparse.ArgumentParser(description=description,epilog=epilog)
	parser.add_argument("--len","-l",action="store",type=int,dest="length",\
		default=1024,help="Specify bits length to generate primes")
	parser.add_argument("--sec","-s",action="store",type=int,dest="sec",\
		default=128,help="Specify the security parameter")
	parser.add_argument("--wrk","-w",action="store",type=int,dest="workers",\
		default=MAX_WORKERS,help="Specify the maximal of workers")
	given_args = parser.parse_args()

	try:
		bits_length = int(given_args.length)
		sec_param = int(given_args.sec)
		max_workers = int(given_args.workers)
	except ValueError as val_err:
		print("[-] Error: {}".format(str(val_err)))
		sys.exit(1)

	print("[!] Warning: This RSA generator doesn't check for safe prime")
	start_time = datetime.now()
	genrsa_obj = GenRSA(bits_length,sec_param)
	try:
		with futures.ThreadPoolExecutor(max_workers=max_workers) as _exec:
			exec = _exec.submit(genrsa_obj.run)
			exec.result()
	except KeyboardInterrupt:
		print("\n[!] Program is shutting down...")
		time.sleep(1)
		sys.exit(1)

	end_time = datetime.now()
	print("[*] Running time: {}".format(end_time-start_time))

if __name__ == "__main__":
	try:
		main()
	except OverflowError as o_err:
		print("[-] Overflow: {}".format(str(o_err)))
		sys.exit(1)
	except KeyboardInterrupt:
		print("\n[!] Program is shutting down...")
		time.sleep(1)
		sys.exit(1)
