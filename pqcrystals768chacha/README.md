CRYSTALS-KYBER has ben chosen recently by NIST for being standardized in Post-Quantum Cryptography. 
We want to test KYBER library to understand their C code and their theory. 


git clone --recurse-submodule https://github.com/pq-crystals/kyber
gcc -c -O3 -fomit-frame-pointer -march=native -fPIC *.c
gcc -shared -o kyberlib.so *.o -z muldefs -L/usr/local/lib/ -lssl -lcrypto
