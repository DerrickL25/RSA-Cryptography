/*********************************************************************************
* numtheory.c
* Contains implementation of arithmetic required for RSA cryptography.
* Includes large number operations and large prime number generation
*********************************************************************************/

#include <stdlib.h>
#include "numtheory.h"
#include "randstate.h"

void gcd(mpz_t d, mpz_t a, mpz_t b) {                   // computes greatest common divisor
  mpz_t copy_b, copy_a, temp, mod;
  mpz_inits(copy_b, copy_a, temp, mod, NULL);           // initializing mpz vars
  mpz_set(copy_b, b);                                   // copying b so original remains unmodified
  mpz_set(copy_a, a);                                   // copying a so original remains unmodified
  while (mpz_cmp_ui(copy_b, 0) != 0) {                  // while b is not 0, loop and find factors
    mpz_set(temp, copy_b);
    mpz_mod(mod, copy_a, copy_b);
    mpz_set(copy_b, mod);
    mpz_set(copy_a, temp);
  }
  mpz_set(d, copy_a);                                   // set output var to a
  mpz_clears(copy_b, copy_a, temp, mod, NULL);          // clear mpz vars initialized inside function
}

void mod_inverse(mpz_t o, mpz_t a, mpz_t n) {           // computes modulo inverse
  mpz_t r1, r2, t1, t2, q, p, m, temp, add;             // initializing mpz vars
  mpz_inits(r1, r2, t1, t2, q, p, m, temp, add, NULL);
  mpz_set(r1, n);
  mpz_set(r2, a);
  mpz_set_ui(t1, 0);
  mpz_set_ui(t2, 1);
  while (mpz_cmp_ui(r2, 0) != 0) {                      // while r' is not equal to 0, loop
    mpz_fdiv_q(q, r1, r2);                              // quotient of r and r'

    mpz_set(temp, r1);                                  // auxiliary variable for r
    mpz_set(r1, r2);
    mpz_mul(p, q, r2);
    mpz_sub(m, temp, p);                                // q * r'
    mpz_set(r2, m);                                     // r - q * r'

    mpz_set(temp, t1);                                  // auxiliary variable for t
    mpz_set(t1, t2);
    mpz_mul(p, q, t2);                                  // q * t'
    mpz_sub(m, temp, p);                                // t - q * t'
    mpz_set(t2, m);
  }
  if (mpz_cmp_ui(r1, 1) > 0) {                          // if r > 1, no inverse
    mpz_set_ui(o, 0);
    mpz_clears(r1, r2, t1, t2, q, p, m, temp, add, NULL);
    return;
  }
  if (mpz_cmp_ui(t1, 0) < 0) {                          // if t < 0, t = t + n
    mpz_add(add, t1, n);
    mpz_set(t1, add);
  }
  mpz_set(o, t1);                                       // set output to t
  mpz_clears(r1, r2, t1, t2, q, p, m, temp, add, NULL);
}

void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {      // computes base**exponent % modulus
  mpz_t p, copy_d, rem, prod, mod, p_prod, p_mod, q, two;
  mpz_inits(p, copy_d, rem, prod, mod, p_prod, p_mod, q, two, NULL);
  mpz_set(copy_d, d);
  mpz_set_ui(o, 1);
  mpz_set(p, a);
  while (mpz_cmp_ui(copy_d, 0) > 0) {                   // while d > 0, loop
    mpz_mod_ui(rem, copy_d, 2);
    if (mpz_cmp_ui(rem, 1) == 0) {                      // if d is odd, o = (o * p) % n
      mpz_mul(prod, o, p);
      mpz_mod(mod, prod, n);
      mpz_set(o, mod);
    }
    mpz_mul(p_prod, p, p);                              // p^2
    mpz_mod(p_mod, p_prod, n);                          // p^2 % n
    mpz_set(p, p_mod);                                  // p = p^2 % n

    mpz_set_ui(two, 2);
    mpz_fdiv_q(q, copy_d, two);                         // floor of d / 2
    mpz_set(copy_d, q);                                 // d = floor of d / 2
  }
  mpz_clears(p, copy_d, rem, prod, mod, p_prod, p_mod, q, two, NULL);
}

bool is_prime(mpz_t n, uint64_t iters) {                // Miller-Rabin primality test
  mpz_t copy_n, start, one, right, floor, ceil, r, rand, y, y2, two;
  mpz_inits(copy_n, start, one, right, floor, ceil, r, rand, y, y2, two, NULL);

  if (mpz_cmp_ui(n, 0) == 0 || mpz_cmp_ui(n, 1) == 0) {          // since program cannot tell if 0-3 are prime or not, this is provided
    return false;
  }
  if (mpz_cmp_ui(n, 3) == 0) {
    return true;
  }

  int s = 0;                                            // exponent s begins at 0
  mpz_set(copy_n, n);
  mpz_set_ui(one, 1);
  mpz_set_ui(two, 2);
  mpz_sub_ui(start, copy_n, 1);
  while (1) {                                           // finds exponent s and odd number r such that n - 1 = 2^s * r
    mpz_mul_2exp(right, one, s);
    mpz_fdiv_q(floor, start, right);
    mpz_cdiv_q(ceil, start, right);
    if (mpz_cmp(floor, ceil) != 0) {                    // break loop if n - 1 / 2^s is no longer an integer
      break;
    }
    s += 1;                      // increment exponent by 1
  }
  s -= 1;                        // find previous s, since current s is the non-integer exponent for n
  
  mpz_mul_2exp(right, one, s);                          // 2^s
  mpz_fdiv_q(r, start, right);                          // r = n - 1 / 2^s

  for (uint64_t i = 1; i < iters; i++) {                // iterates through specified num of iters
    while (1) {
      mpz_urandomm(rand, state, start);                 // find random number 2 to n - 2, inclusive
      if (mpz_cmp_ui(rand, 1) > 0) {
        break;
      }
    }
    pow_mod(y, rand, r, copy_n);                        // Miller-Rabin primality test
    if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, start) != 0) {
      int j = 1;
      while (j <= s - 1 && mpz_cmp(y, start) != 0) {
        pow_mod(y2, y, two, copy_n);
        mpz_set(y, y2);                                 // auxiliary temp variable for y
        if (mpz_cmp_ui(y, 1) == 0) {
          mpz_clears(copy_n, start, one, right, floor, ceil, r, rand, y, y2, two, NULL);
          return false;                                 // return false if y == 1
        }
        j += 1;
      }
      if (mpz_cmp(y, start) != 0) {                     // return false if y != n - 1
        mpz_clears(copy_n, start, one, right, floor, ceil, r, rand, y, y2, two, NULL);
        return false;
      }
    }
  }
  mpz_clears(copy_n, start, one, right, floor, ceil, r, rand, y, y2, two, NULL);
  return true;                                          // clear mpz vars initialized inside function and return true
}

void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {           // generates random numbers until a prime is found
  while (1) {
    mpz_urandomb(p, state, bits);
    if (mpz_sizeinbase(p, 2) == bits) {                 // get a rand num exactly 'bits' long
      if (mpz_even_p(p) != 0) {                         // if it is even, make it odd
        mpz_add_ui(p, p, 1);
      }
      int cont = 0;                                     // if this is 1, it will go to the next iter of the while loop
      for (int i = 3; i < 542; i += 2) {                // checks if the random num is divisible by a bunch of odd nums to filter out nums that cannot be prime
        if (mpz_divisible_ui_p(p, i) == 1 && mpz_cmp_ui(p, i) != 0) {
          cont = 1;
          break;                                        // sets cont = 1, so remainder of while loop is skipped; is_prime is skipped for this number
        }
      }
      if (cont == 1) {
        continue;
      }
      if (is_prime(p, iters) == 1) {                    // this will only run if the number passes the filter
        break;
      }
    }
  }
}
