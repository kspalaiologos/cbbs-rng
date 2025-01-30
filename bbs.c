// ---------------------------------------------------------------------------
//      General research implementation of the Blum Blum Shub
//      random number generator. Written and released to the public
//      domain by Kamila Szewczyk.
// ---------------------------------------------------------------------------
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

// Define s.t. desired log2(pq) --> N_BITS.
#define N_BITS 512
typedef unsigned _BitInt(N_BITS) bbsint;
typedef signed _BitInt(N_BITS) sbbsint;
typedef unsigned _BitInt(N_BITS * 2) bbs2int;
typedef unsigned _BitInt(N_BITS * 4) bbs4int;

// ---------------------------------------------------------------------------
//      Cryptographically secure random number source. Used
//      for seeding the generator. Supports DOS, Windows and *NIX platforms.
// ---------------------------------------------------------------------------
static void eprintf(const char * fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  exit(1);
}

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
static HCRYPTPROV hp;
static void init_secrandom(void) {
  CryptAcquireContext(&hp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
}
static void secrandom(void * buf, size_t len) {
  CryptGenRandom(hp, len, buf);
}
#elif __unix__
#include <fcntl.h>
#include <unistd.h>
static int fd;
static void init_secrandom(void) {
  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    eprintf("Could not open `/dev/urandom': %s\n", strerror(errno));
}
static void secrandom(void * buf, size_t len) {
  read(fd, buf, len);
}
#elif __MSDOS__
static FILE * f;
static void init_secrandom(void) {
  f = fopen("/dev/urandom$", "rb");
  if (!f)
    eprintf("Could not open `/dev/urandom$': %s\n", strerror(errno));
}
static void secrandom(void * buf, size_t len) { // Doug Kaufman's NOISE.SYS
  fread(buf, 1, len, f);
}
#endif

// ---------------------------------------------------------------------------
//      Low-level, preliminary primality test (fixed size sieve).
//      Assumes that inputs to the algorithm `p' are p <= 2^(N_BITS - 1).
//      and further p mod 4 = 3. Uses Barrett's algorithm for division.
// ---------------------------------------------------------------------------
#define NPRIMES 99
static const unsigned primes[NPRIMES] = {
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
  71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
  151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
  233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
  317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
  419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
  503, 509, 521, 523
};
static bbsint prime_barrett[NPRIMES];
static void init_prime_quotients(void) {
  for (unsigned i = 0; i < NPRIMES; i++)
    prime_barrett[i] = ((bbsint) -1) / primes[i] + 1;
}
static int is_prime_low(bbsint n) {
  for (unsigned i = 0; i < NPRIMES; i++)
    if (n * prime_barrett[i] <= prime_barrett[i] - 1) return 0;
  return 1;
}

// ---------------------------------------------------------------------------
//      High-level probabilistic primality test (Miller-Rabin).
//      Assumptions are the same as for the low-level test.
//      Uses binary exponentiation with Barrett reductions for speed.
// ---------------------------------------------------------------------------
static int ilog2(bbsint n) { int l = 0; while (n >>= 1) l++; return l; }
static bbsint csrand(bbsint max, int ilog) {
  for (;;) {
    bbsint r; secrandom(&r, N_BITS / 8);
    if ((r >>= N_BITS - ilog) < max) return r;
  }
}
static bbsint modexp(bbsint base, bbsint e, bbsint mod, bbs2int M) {
  bbsint r = 1;
  base = ((bbs4int) (M * base) * mod) >> (N_BITS * 2);
  while (e) {
    if (e & 1)
      r = ((bbs4int) (M * ((bbs2int) r * base)) * mod) >> (N_BITS * 2);
    base = ((bbs4int) (M * ((bbs2int) base * base)) * mod) >> (N_BITS * 2);
    e >>= 1;
  }
  return r;
}
static int is_prime_high(bbsint n, int iter) {
  int s = 0;  bbsint d = n - 1;
  while ((d & 1) == 0) { d >>= 1; s++; }
  int ilog = ilog2(n - 3);
  const bbs2int M = ((bbs2int) -1) / n + 1;
  for (int i = 0; i < iter; i++) {
    bbsint a = 2 + csrand(n - 3, ilog);
    bbsint x = modexp(a, d, n, M);
    if (x == 1 || x == n - 1)
      continue;
    int c = 0;
    for (int r = 1; r < s; r++) {
      x = ((bbs4int) (M * (x * x)) * n) >> (N_BITS * 2);
      if (x == n - 1) { c = 1; break; }
    }
    if(!c) return 0;
  }
  return 1;
}

// ---------------------------------------------------------------------------
//      Prime number generation for the BBS algorithm. Resulting p, q are
//      Sophie Germain-safe primes.
//      Yields correct results in 99.99999999999999999999999999999999997%
//      of the cases (2^-128 error rate due to ROUNDS = 64 in Miller-Rabin).
//      `gcd((p-3)/2, (q-3)/2)' should be small for maximised
//      period length. Not strictly necessary; nmplemented here.
// ---------------------------------------------------------------------------
static void generate_primes(bbsint * p1, bbsint * p2) {
  bbsint p, q;  const int ROUNDS = 64;
  do {
    p = csrand(((bbsint) 1) << (N_BITS / 2), N_BITS / 2); p |= 0b11;
  } while (!is_prime_low(p) || !is_prime_high(p, ROUNDS)
        || !is_prime_low(2 * p + 1) || !is_prime_high(2 * p + 1, ROUNDS)); 
  do {
    q = csrand(((bbsint) 1) << (N_BITS / 2), N_BITS / 2); q |= 0b11;
  } while (p == q || !is_prime_low(q) || !is_prime_high(q, ROUNDS)
        || !is_prime_low(2 * q + 1) || !is_prime_high(2 * q + 1, ROUNDS));
  *p1 = 2 * p + 1; *p2 = 2 * q + 1;
}

// ---------------------------------------------------------------------------
//      Greatest common divisor via Stein's algorithm.
// ---------------------------------------------------------------------------
int ctz(bbsint n) {
  int c = 0; while ((n & 1) == 0 && n != 0) { n >>= 1; c++; } return c;
}
bbsint gcd(bbsint a, bbsint b) {
  if (!a) return b; if (!b) return a;
  int az = ctz(a), bz = ctz(b);
  int shift = az < bz ? az : bz;
  b >>= bz;
  while (a != 0) {
    a >>= az;
    sbbsint diff = ((sbbsint) b) - a;
    az = ctz(diff);
    b = a < b ? a : b;
    a = diff < 0 ? -diff : diff;
    if (a == b) return a;
  }
  return b << shift;
}

// ---------------------------------------------------------------------------
//      Interface to the Blum Blum Shub generator.
// ---------------------------------------------------------------------------
typedef struct { bbsint pq, x, x0, c; bbs2int cache, Mc; int pos; } bbs_t;
static void bbs_new(bbs_t * bbs) {
  bbsint p, q;  generate_primes(&p, &q);
  bbs->pq = p * q;
  for (;;) {
    bbs->x = csrand(bbs->pq, ilog2(bbs->pq));
    if (bbs->x <= 1) continue;
    if (bbs->x % p != 0 && bbs->x % q != 0) break;
  }
  bbs->x0 = bbs->x;
  bbs->cache = ((bbs2int) -1) / bbs->pq + 1;
  bbs->c = (p - 1) * (q - 1) / gcd(p - 1, q - 1);
  bbs->Mc = ((bbs2int) -1) / bbs->c + 1;
  bbs->pos = 0;
}
static void bbs_step(bbs_t * bbs) {
  bbs2int sq = ((bbs2int) bbs->x) * bbs->x;
  bbs->x = ((bbs4int) (bbs->cache * sq) * bbs->pq) >> (N_BITS * 2);
  bbs->pos++;
}
static void bbs_set(bbs_t * bbs, int i) {
  bbsint arg = modexp(2, i, bbs->c, bbs->Mc);
  bbs->x = modexp(bbs->x0, arg, bbs->pq, bbs->cache);
  bbs->pos = i;
}
static bbsint bbs_next(bbs_t * bbs, int bits) {
  bbsint r = 0;
  for (int i = bits; i != 0; --i) {
    bbs_step(bbs); r = (r << 1) | (bbs->x & 1);
  }
  return r;
}
static uint64_t bbs_next64(bbs_t * bbs) {
  uint64_t r = 0;
  for (int i = 64; i != 0; --i) {
    bbs_step(bbs); r = (r << 1) | (bbs->x & 1);
  }
  return r;
}

// ---------------------------------------------------------------------------
//      CLI stub. By default, the program will output
//      an infinite stream of random numbers to stdout (64-bit,
//      native endian). If changed, it displays an experiment.
// ---------------------------------------------------------------------------
#if 1
int main(void) {
  init_secrandom();  init_prime_quotients();
  bbs_t bbs;  bbs_new(&bbs);
  for (;;) {
    uint64_t r = bbs_next64(&bbs);
    fwrite(&r, 1, 8, stdout);
  }
}
#else
int main(void) {
  init_secrandom();  init_prime_quotients();
  bbs_t bbs;  bbs_new(&bbs);
  printf("First 10 outputs (64-bit):\n");
  for (int i = 0; i < 10; i++)
    printf("%016lx\n", bbs_next64(&bbs));
  printf("Next 10 outputs (64-bit) - position %d:\n", bbs.pos);
  for (int i = 0; i < 10; i++)
    printf("%016lx\n", bbs_next64(&bbs));
  bbs_set(&bbs, 64);
  printf("Rewinding back to after 1st output: %d:\n", bbs.pos);
  for (int i = 0; i < 10; i++)
    printf("%016lx\n", bbs_next64(&bbs));
}
#endif
