/*********************************************************************************
* encrypt.c
* Encrypts a file with a public RSA key
* Usage guide in README.md
*********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"
// clang-format on

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {
  FILE *infile = stdin;                     // default input set to stdin
  FILE *outfile = stdout;                   // default output set to stdout
  char pub_file[] = "rsa.pub";              // default public key file
  char input[300];                          // initializing username string array
  int verbose = 0;                          // verbose set to false
  int opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'i':                               // specify input file to encrypt and exit if it is invalid
      infile = fopen(optarg, "r");
      if (infile == NULL) {
        gmp_fprintf(stderr, "could not open %s: no such file or directory\n", optarg);
        return 1;
      }
      break;
    case 'o':                               // specify output file to write ciphertext to
      outfile = fopen(optarg, "w");
      break;
    case 'n':                               // specify file containing public key
      strcpy(pub_file, optarg);
      break;
    case 'v':                               // enable verbose output
      verbose = 1;
      break;
    case 'h':                               // prints program usage and synopsis
      gmp_fprintf(
          stderr,
          "Usage: ./encrypt [options]\n  ./encrypt encrypts an input file "
          "using the specified public key file,\n  writing the result to the "
          "specified output file.\n    -i <infile> : Read input from <infile>. "
          "Default: standard input.\n    -o <outfile>: Write output to "
          "<outfile>. Default: standard output.\n    -n <keyfile>: Public key "
          "is in <keyfile>. Default: rsa.pub.\n    -v          : Enable "
          "verbose output.\n    -h          : Display program synopsis and "
          "usage.\n");
      fclose(infile);
      fclose(outfile);
      return 0;
    default:                                // print -h output and exit program on bad option
      gmp_fprintf(
          stderr,
          "Usage: ./encrypt [options]\n  ./encrypt encrypts an input file "
          "using the specified public key file,\n  writing the result to the "
          "specified output file.\n    -i <infile> : Read input from <infile>. "
          "Default: standard input.\n    -o <outfile>: Write output to "
          "<outfile>. Default: standard output.\n    -n <keyfile>: Public key "
          "is in <keyfile>. Default: rsa.pub.\n    -v          : Enable "
          "verbose output.\n    -h          : Display program synopsis and "
          "usage.\n");
      fclose(infile);
      fclose(outfile);
      return 1;
    }
  }
  FILE *pub_fs = fopen(pub_file, "r");      // opens specified public file
  if (pub_fs == NULL) {                     // exits program if file cannot be opened
    gmp_fprintf(stderr, "cannot open specified public key file");
    fclose(infile);
    fclose(outfile);
    fclose(pub_fs);
    return 1;
  }
  mpz_t n, e, s, username;
  mpz_inits(n, e, s, username, NULL);       // initializing mpz vars
  rsa_read_pub(n, e, s, input, pub_fs);     // reading key from public key file
  if (verbose == 1) {                       // prints verbose output
    gmp_fprintf(stderr,
                "username: %s\nuser signature(%lu bits): %Zd\nn - modulus (%lu "
                "bits): %Zd\ne - public exponent (%lu bits): %Zd\n",
                input, mpz_sizeinbase(s, 2), s, mpz_sizeinbase(n, 2), n,
                mpz_sizeinbase(e, 2), e);
  }
  mpz_set_str(username, input, 62);                     // converts username into an mpz_t
  if (rsa_verify(username, s, e, n) == false) {         // verifies signature; if it cannot verify, exit program
    gmp_fprintf(stderr, "could not verify signature\n");
    fclose(infile);
    fclose(outfile);
    fclose(pub_fs);
    mpz_clears(n, e, s, username, NULL);
    return 1;
  }
  rsa_encrypt_file(infile, outfile, n, e);              // encrypts input file and writes output to output file

  fclose(infile);                                       // closing file streams and clearing mpz vars
  fclose(outfile);
  fclose(pub_fs);
  mpz_clears(n, e, s, username, NULL);
  return 0;
}
