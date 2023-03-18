/*********************************************************************************
* rsa.c
* Contains RSA key generation, encryption, and decryption functionality
*********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {           // makes a public key and stores it in mpz vars
  mpz_t lambda, phi, den, pminus1, qminus1, rand2;
  mpz_inits(lambda, phi, den, pminus1, qminus1, rand2, NULL);

  uint64_t pbits, qbits, rand;
  uint64_t lower = nbits / 4;                                       // lower bound for rand num = n / 4
  uint64_t upper = (nbits * 3) / 4;                                 // upper bound for rand num = 3n / 4

  while (1) {                             // finds random num between lower and upper bounds
    rand = random() % upper;
    if (rand < lower) {
      continue;
    }
    break;
  }
  pbits = rand;                           // pbits = newfound rand num
  qbits = nbits - pbits;                  // qbits gets the remaining bits, nbits - pbits
  make_prime(p, pbits, iters);            // make a prime and store it in p
  make_prime(q, qbits, iters);            // make a prime and store it in q
  mpz_mul(n, p, q);                       // n = product of p and q

  mpz_sub_ui(pminus1, p, 1);
  mpz_sub_ui(qminus1, q, 1);
  mpz_mul(phi, pminus1, qminus1);         // equivalent to totient(n)
  gcd(den, pminus1, qminus1);
  mpz_fdiv_q(lambda, phi, den);           // calculating lambda(n) with Carmichael's function

  while (1) {                             // find a public exponent e
    mpz_urandomb(rand2, state, nbits);
    if (mpz_sizeinbase(rand2, 2) == nbits) {
      gcd(e, rand2, lambda);
      if (mpz_cmp_ui(e, 1) == 0) {        // break once e is found; e coprime to lambda(n)
        mpz_set(e, rand2);
        break;
      }
    }
  }
  mpz_clears(lambda, phi, den, pminus1, qminus1, rand2, NULL);
}

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {                  // writes public key to a specified file
  gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
}

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {                   // reads public key from a specified file
  gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
}

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {                   // makes a private key and stores it in mpz vars
  mpz_t lambda, phi, gcd2, pminus1, qminus1;
  mpz_inits(lambda, phi, gcd2, pminus1, qminus1, NULL);
  mpz_sub_ui(pminus1, p, 1);
  mpz_sub_ui(qminus1, q, 1);
  mpz_mul(phi, pminus1, qminus1);                                          // equivalent to totient(n, or pq)
  gcd(gcd2, pminus1, qminus1);
  mpz_fdiv_q(lambda, phi, gcd2);                                           // calculating lambda(n) with Carmichael's function
  mod_inverse(d, e, lambda);                                               // private key d = modulo inverse of e and lambda(n)
  mpz_clears(lambda, phi, gcd2, pminus1, qminus1, NULL);
}

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {                      // writes private key to specified file
  gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {                       // reads private key from specified file
  gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {                     // encrypts message m and stores it in ciphertext c using n and e
  pow_mod(c, m, e, n);
}

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {     // encrypts input file and writes to output file using n and e
  mpz_t m, c;
  mpz_inits(m, c, NULL);

  uint64_t k = (mpz_sizeinbase(n, 2) - 1) / 8;                             // size of the block, in bytes
  uint8_t *block = (uint8_t *)malloc(k);                                   // allocating k bytes for the block itself
  block[0] = 0xFF;                                                         // prepends a byte of 1's to the block
  uint64_t j;

  while (feof(infile) != 1) {                                              // while EOF is not reached, loop
    j = fread(block + 1, 1, k - 1, infile);                                // j is set to num of bytes actually read from the input file
    if (j == 0) { // if no bytes are read, break
      break;
    }
    mpz_import(m, j + 1, 1, sizeof(char), 1, 0, block);                    // write j + 1 bytes from m into the block
    if (mpz_cmp_ui(m, 0) == 0 || mpz_cmp_ui(m, 1) == 0) {                  // can't encrypt blocks that are 0 or 1 in value
      gmp_fprintf(stderr, "cannot encrypt block that has value of 0 or 1\n");
      continue;
    }
    rsa_encrypt(c, m, e, n);                                               // encrypts message m into ciphertext c
    gmp_fprintf(outfile, "%Zx\n", c);                                      // writes hexstring to outfile
  }
  mpz_clears(m, c, NULL);
  free(block);
}

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {                     // decrypts ciphertext c into message m
  pow_mod(m, c, d, n);
}

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {     // decrypts input file and writes to output file using n and d
  mpz_t m, c;
  mpz_inits(m, c, NULL);

  uint64_t k = (mpz_sizeinbase(n, 2) - 1) / 8;                             // block size, in bytes
  uint8_t *block = (uint8_t *)malloc(k);                                   // malloc size of block
  size_t j = 0;

  while (feof(infile) != 1) {                                               // while EOF not reached, loop
    gmp_fscanf(infile, "%Zx\n", c);                                         // scan in hexstring
    rsa_decrypt(m, c, d, n);                                                // decrypt hexstring into message m
    mpz_export(block, &j, 1, sizeof(char), 1, 0, m);                        // writes j byes from the block into m
    fwrite(block + 1, 1, j - 1, outfile);                                   // write j - 1 bytes from the block into the output
  }
  mpz_clears(m, c, NULL);
  free(block);
}

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {                         // performs RSA signing on m using d and n
  pow_mod(s, m, d, n);
}

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {                       // signature verification
  mpz_t t;
  mpz_init(t);

  pow_mod(t, s, e, n);
  if (mpz_cmp(t, m) == 0) {
    return true;
  } else {
    return false;
  }
  mpz_clear(t);
}
