/*********************************************************************************
* keygen.c
* Generates public/private key pairs of variable size and randomness
* Usage guide in README.md
*********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#define OPTIONS "b:i:n:d:s:vh"

int main(int argc, char **argv) {
  uint64_t nbits = 1024;              // default num of bits: 1024
  uint64_t mr_iters = 50;             // default num of iterations for Miller-Rabin
  char pub_file[] = "rsa.pub";        // default public key file
  char priv_file[] = "rsa.priv";      // default private key file
  uint64_t seed = time(NULL);         // default seed set to num of seconds since Unix epoch
  int verbose = 0;                    // verbose set to false
  int opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'b':                         // specify num of bits for n and exit if input is invalid
      nbits = strtoul(optarg, NULL, 10);
      if (nbits < 50 || nbits > 4096) {
        gmp_fprintf(stderr, "number of bits must be within 50-4096, inclusive.\n");
        return 1;
      }
      break;
    case 'i':                         // specify num of iters for Miller-Rabin and exit if input is invalid
      mr_iters = strtoul(optarg, NULL, 10);
      if (mr_iters < 1 || nbits > 500) {
        gmp_fprintf(stderr, "number of iterations must be within 1-500, inclusive.\n");
        return 1;
      }
      break;
    case 'n':                         // specify file to write public key to
      strcpy(pub_file, optarg);
      break;
    case 'd':                         // specify file to write private key to
      strcpy(priv_file, optarg);
      break;
    case 's':                         // specify seed to initialize random state to
      seed = strtoul(optarg, NULL, 10);
      break;
    case 'v':                         // enable verbose output
      verbose = 1;
      break;
    case 'h':                         // prints program usage and synopsis
      gmp_fprintf(
          stderr,
          "Usage: ./keygen [options]\n  ./keygen generates a public / private "
          "key pair, placing the keys into the public and private\n  key files "
          "as specified below. The keys have a modulus (n) whose length is "
          "specified in\n  the program options.\n    -s <seed>   : Use <seed> "
          "as the random number seed. Default: time()\n    -b <bits>   : "
          "Public modulus n must have at least <bits> bits. Default: 1024\n    "
          "-i <iters>  : Run <iters> Miller-Rabin iterations for primality "
          "testing. Default: 50\n    -n <pbfile> : Public key file is "
          "<pbfile>. Default: rsa.pub\n    -d <pvfile> : Private key file is "
          "<pvfile>. Default: rsa.priv\n    -v          : Enable verbose "
          "output.\n    -h          : Display program synopsis and usage.\n");
      return 0;
    default:                          // print -h output and exit the program on bad option
      gmp_fprintf(
          stderr,
          "Usage: ./keygen [options]\n  ./keygen generates a public / private "
          "key pair, placing the keys into the public and private\n  key files "
          "as specified below. The keys have a modulus (n) whose length is "
          "specified in\n  the program options.\n    -s <seed>   : Use <seed> "
          "as the random number seed. Default: time()\n    -b <bits>   : "
          "Public modulus n must have at least <bits> bits. Default: 1024\n    "
          "-i <iters>  : Run <iters> Miller-Rabin iterations for primality "
          "testing. Default: 50\n    -n <pbfile> : Public key file is "
          "<pbfile>. Default: rsa.pub\n    -d <pvfile> : Private key file is "
          "<pvfile>. Default: rsa.priv\n    -v          : Enable verbose "
          "output.\n    -h          : Display program synopsis and usage.\n");
      return 1;
    }
  }
  FILE *pub_fs = open(pub_file, "w");               // open file stream for specified public key file
  FILE *priv_fs = open(priv_file, "w"); // open file stream for specified private key file
  if (pub_fs == NULL) {      // exit program if file cannot be opened
    gmp_fprintf(stderr, "cannot open specified public key file\n");
    if (priv_fs != NULL) {
      fclose(priv_fs);
    }
    return 1;
  }
  if (priv_fs == NULL) {                            // exit program if file cannot be opened
    gmp_fprintf(stderr, "cannot open specified private key file\n");
    if (pub_fs != NULL) {
      fclose(pub_fs);
    }
    return 1;
  }
  fchmod(fileno(priv_fs), 0600);                    // setting file permissions for private key to user only
  randstate_init(seed);                             // initializing state with specified seed
  mpz_t d, p, q, n, e, username, sig;
  mpz_inits(d, p, q, n, e, username, sig, NULL);    // initializing mpz vars

  rsa_make_pub(p, q, n, e, nbits, r_iters);         // makes public key and sets to mpz vars
  rsa_make_priv(d, e, p, q); // makes private key and sets to mpz vars

  char *input = getenv("USER");                     // gets user's name from environment variable
  mpz_set_str(username, input, 62);                 // sets the name to the mpz var 'username'
  rsa_sign(sig, username, d, n);                    // RSA signs the mpz var 'username'

  rsa_write_pub(n, e, sig, input, pub_fs);          // writes public key to specified file
  rsa_write_priv(n, d, priv_fs);                    // writes private key to specified file

  if (verbose == 1) {                               // verbose output
    gmp_fprintf(
        stderr,
        "username: %s\nuser signature(%lu bits): %Zd\np (%lu bits): %Zd\nq "
        "(%lu bits): %Zd\nn - modulus (%lu bits): %Zd\ne - public exponent "
        "(%lu bits): %Zd\nd - private exponent (%lu bits): %Zd\n",
        input, mpz_sizeinbase(sig, 2), sig, mpz_sizeinbase(p, 2), p,
        mpz_sizeinbase(q, 2), q, mpz_sizeinbase(n, 2), n, mpz_sizeinbase(e, 2),
        e, mpz_sizeinbase(d, 2), d);
  }
  fclose(pub_fs);                                   // closing file streams and clearing mpz vars
  fclose(priv_fs);
  mpz_clears(d, p, q, n, e, username, sig, NULL);
  return 0;
}
