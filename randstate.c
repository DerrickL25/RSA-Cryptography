/*********************************************************************************
* randstate.c
* Sets random state for key generation
*********************************************************************************/

#include <stdlib.h>
#include "randstate.h"

gmp_randstate_t state;

void randstate_init(uint64_t seed) {                       // Initializes the random state needed for RSA key generation operations; can be seeded
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, seed);
  srandom(seed);
}

void randstate_clear(void) { gmp_randclear(state); }       // Frees any memory used by the initialized random state

