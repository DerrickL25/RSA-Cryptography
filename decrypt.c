/*********************************************************************************
* decrypt.c
* Decrypts cyphertext file with a private RSA key
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

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {
  FILE *infile = stdin;                         // default input set to stdin
  FILE *outfile = stdout;                       // default output set to stdout
  char priv_file[] = "rsa.priv";                // default private key file
  int verbose = 0;                              // verbose set to false
  int opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'i':                                   // specify input file to decrypt and exit if it is invalid
      infile = fopen(optarg, "r");
      if (infile == NULL) {
        gmp_fprintf(stderr, "could not open %s: no such file or directory\n", optarg);
        return 1;
      }
      break;
    case 'o':                                   // specify output file to write decrypted text to
      outfile = fopen(optarg, "w");
      break;
    case 'n':                                   // specify file containing private key
      strcpy(priv_file, optarg);
      break;
    case 'v':                                   // enable verbose output
      verbose = 1;
      break;
    case 'h':                                   // prints program usage and synopsis
      gmp_fprintf(
          stderr,
          "Usage: ./decrypt [options]\n  ./decrypt decrypts an input file "
          "using the specified private key file,\n  writing the result to the "
          "specified output file.\n    -i <infile> : Read input from <infile>. "
          "Default: standard input.\n    -o <outfile>: Write output to "
          "<outfile>. Default: standard output.\n    -n <keyfile>: Private key "
          "is in <keyfile>. Default: rsa.priv.\n    -v          : Enable "
          "verbose output.\n    -h          : Display program synopsis and "
          "usage.\n");
      fclose(infile);
      fclose(outfile);
      return 0;
    default:                                    // prints -h output and exit program on bad option
      gmp_fprintf(
          stderr,
          "Usage: ./decrypt [options]\n  ./decrypt decrypts an input file "
          "using the specified private key file,\n  writing the result to the "
          "specified output file.\n    -i <infile> : Read input from <infile>. "
          "Default: standard input.\n    -o <outfile>: Write output to "
          "<outfile>. Default: standard output.\n    -n <keyfile>: Private key "
          "is in <keyfile>. Default: rsa.priv.\n    -v          : Enable "
          "verbose output.\n    -h          : Display program synopsis and "
          "usage.\n");
      fclose(infile);
      fclose(outfile);
      return 1;
    }
  }
  FILE *priv_fs = fopen(priv_file, "r");        // opening file stream for private key file
  if (priv_fs == NULL) {                        // exits program if file cannot be opened
    gmp_fprintf(stderr, "cannot open specified private key file");
    fclose(infile);
    fclose(outfile);
    fclose(priv_fs);
    return 1;
  }
  mpz_t n, d;
  mpz_inits(n, d, NULL);                        // initializing mpz vars

  rsa_read_priv(n, d, priv_fs);                 // reading private key from file

  if (verbose == 1) { // verbose output
    gmp_fprintf(
        stderr,
        "n - modulus (%lu bits): %Zd\nd - private exponent (%lu bits): %Zd\n",
        mpz_sizeinbase(n, 2), n, mpz_sizeinbase(d, 2), d);
  }
  rsa_decrypt_file(infile, outfile, n, d);      // decrypting input file and writing to output file

  fclose(infile);                               // closing file streams and clearing mpz vars
  fclose(outfile);
  fclose(priv_fs);
  mpz_clears(n, d, NULL);
  return 0;
}
