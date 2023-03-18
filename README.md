# RSA-Cryptography
As part of a school project, I wrote a barebones RSA cryptography program in C capable of generating key pairs of varying size, and file encryption/decryption.
The following is a usage guide.

This program generates RSA key pairs, encrypts, and decrypts files. Generating keys, encrypting files,
and decrypting files each have their own executable and take in arguments. The following will specify
how to use these executables. Run "make" to compile and link the files in the directory before running
the program.  
keygen:  
"-b": specify number of bits for the public modulus n (default: 1024).  
"-i": specify number of iterations for the Miller-Rabin primality test (default: 50).  
"-n": specify the public key file to write the key to (default: "rsa.pub").  
"-d": specify the private key file to write the key to (default: "rsa.priv").  
"-s": specify the seed used to initialize the random state (default: seconds since Unix epoch).  
"-v": enables verbose output.  
"-h": displays program synopsis and usage.  
encrypt:  
"-i": specify input file to encrypt (default: stdin).  
"-o": specify output of the encrypted input (default: stdout).  
"-n": specify file containing public key (default: "rsa.pub").  
"-v": enables verbose output.  
"-h": displays program synopsis and usage.  
decrypt:  
"-i": specify input file to decrypt (default: stdin).  
"-o": specify output of the decrypted input (default: stdout).  
"-n": specify file containing private key (default: "rsa.priv").  
"-v": enables verbose output.  
"-h": displays program synopsis and usage.  
Included files:  
randstate.c and randstate.h: sets the random state for gmp and stdlib random functions given a seed.  
