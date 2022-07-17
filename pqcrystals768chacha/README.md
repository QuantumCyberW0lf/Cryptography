git clone --recurse-submodule https://github.com/pq-crystals/kyber
gcc -c -O3 -fomit-frame-pointer -march=native -fPIC *.c
gcc -shared -o kyberlib.so *.o -z muldefs -L/usr/local/lib/ -lssl -lcrypto
