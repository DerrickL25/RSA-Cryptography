/*********************************************************************************
* numtheory.h
* Interface for numtheory.c
*********************************************************************************/

#pragma once

#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void gcd(mpz_t d, mpz_t a, mpz_t b);                          // greatest common divisor of large numbers

void mod_inverse(mpz_t o, mpz_t a, mpz_t n);                  // modular inverse of large numbers

void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n);             // modular exponentiation of large numbers

bool is_prime(mpz_t n, uint64_t iters);                       // prime checking based on the Miller-Rabin primality test

void make_prime(mpz_t p, uint64_t bits, uint64_t iters);      // prime number generation through random seeding
