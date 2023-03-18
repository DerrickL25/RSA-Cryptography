/*********************************************************************************
* randstate.h
* Interface for randstate.c
*********************************************************************************/

#pragma once

#include <gmp.h>
#include <stdint.h>

extern gmp_randstate_t state;              

void randstate_init(uint64_t seed);        // Initializes the random state needed for RSA key generation operations; can be seeded

void randstate_clear(void);                // Frees any memory used by the initialized random state
