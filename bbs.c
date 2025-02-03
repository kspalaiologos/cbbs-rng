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
#include <math.h>
#include <errno.h>

#ifdef OPENMP
  #include <omp.h>
#endif

// ---------------------------------------------------------------------------
//      Bit integers and OpenMP detection code.
// ---------------------------------------------------------------------------
// Define s.t. desired log2(pq) --> N_BITS.
// For tangible security set at least N_BITS = 8192.
// For demonstration, set N_BITS = 512.
#define N_BITS 8192

typedef unsigned _BitInt(N_BITS) bbsint;
typedef unsigned _BitInt(N_BITS * 2) bbs2int;

#if N_BITS > 1024
  #ifndef OPENMP
    #error "That won't work."
  #endif
#endif

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
//      Pre-generates primes via the Sieve of Atkin.
//      Assumes that inputs to the algorithm `p' are p <= 2^(N_BITS - 1).
//      and further p mod 4 = 3. Also uses Fermat's little theorem.
// ---------------------------------------------------------------------------
#define NPRIMES 2048
static unsigned primes[NPRIMES];
static bbs2int barrett_cache[NPRIMES];
static void populate_barrett_cache(void) {
  int limit = NPRIMES * log2(NPRIMES) * 1.2;
  if (limit < 2) limit = 2;
  char * is_prime = calloc(limit + 1, 1);
  is_prime[2] = 1;
  is_prime[3] = 1;
  for (int x = 1; x * x <= limit; x++) {
    for (int y = 1; y * y <= limit; y++) {
      int n = 4 * x * x + y * y;
      if (n <= limit && (n % 12 == 1 || n % 12 == 5))
        is_prime[n] = !is_prime[n];
      n = 3 * x * x + y * y;
      if (n <= limit && n % 12 == 7)
        is_prime[n] = !is_prime[n];
      n = 3 * x * x - y * y;
      if (x > y && n <= limit && n % 12 == 11)
        is_prime[n] = !is_prime[n];
    }
  }
  for (int r = 5; r * r <= limit; r++)
    if (is_prime[r])
      for (int i = r * r; i <= limit; i += r * r)
        is_prime[i] = 0;
  int count = 0;
  for (int i = 2; i <= limit && count < NPRIMES; i++)
    if (is_prime[i]) primes[count++] = i;
  free(is_prime);
  for (unsigned i = 0; i < NPRIMES; i++)
    barrett_cache[i] = ((bbs2int) -1) / primes[i] + 1;
}
static bbsint modexp_half(bbsint base, bbsint e, bbsint mod) {
  bbsint r = 1;
  while (e) {
    if (e & 1)
      r = r * base % mod;
    base = base * base % mod;
    e >>= 1;
  }
  return r;
}
static int is_prime_low(bbsint n) {
  for (unsigned i = 0; i < NPRIMES; i++)
    if (barrett_cache[i] * n < barrett_cache[i]) return 0;
  return modexp_half(2, n - 1, n) == 1; // Fermat.
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
static int is_prime_high(bbsint n, int iter) {
  int s = 0;  bbsint d = n - 1;
  while ((d & 1) == 0) { d >>= 1; s++; }
  int ilog = ilog2(n - 3);
  for (int i = 0; i < iter; i++) {
    bbsint a = 2 + csrand(n - 3, ilog);
    bbsint x = modexp_half(a, d, n);
    if (x == 1 || x == n - 1)
      continue;
    int c = 0;
    for (int r = 1; r < s; r++) {
      x = x * x % n;
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
//      Per Bertrand postulate we always find a suitable prime.
//      
//      Optimisation:
//      We know that k = (p - 1)/2 (so p = 2k + 1) is prime. Then
//      2^(p - 1) = 1 (mod p) implies that p is prime as well.
// ---------------------------------------------------------------------------
#ifndef OPENMP
  static void generate_primes(bbsint * p1, bbsint * p2) {
    bbsint p, q, r;  const int ROUNDS = 64;
    do {
      p = csrand((((bbsint) 1) << (N_BITS / 2 - 2)), N_BITS / 2 - 2);
      p |= 0b11; r = 2 * p + 1;
    } while (!is_prime_low(r) || !is_prime_high(r, ROUNDS)
          || modexp_half(2, r - 1, r) != 1);
    do {
      q = csrand((((bbsint) 1) << (N_BITS / 2 - 2)), N_BITS / 2 - 2);
      q |= 0b11; r = 2 * q + 1;
    } while (p == q || !is_prime_low(r) || !is_prime_high(r, ROUNDS)
           || modexp_half(2, r - 1, r) != 1);
    *p1 = 2 * p + 1; *p2 = 2 * q + 1;
  }
#else
  static void generate_primes(bbsint * p1, bbsint * p2) {
    const int ROUNDS = 64;  _Atomic(int) found;
    found = 0;
    #pragma omp parallel for
    for (int i = 0; i < omp_get_num_threads(); i++) {
      bbsint p, r;
      do {
        p = csrand((((bbsint) 1) << (N_BITS / 2 - 2)), N_BITS / 2 - 2);
        p |= 0b11; r = 2 * p + 1;
      } while (!found && (!is_prime_low(r) || !is_prime_high(r, ROUNDS)
            || modexp_half(2, r - 1, r) != 1));
      #pragma omp critical
      { if (!found) *p1 = 2 * p + 1, found = 1; }
    }
    found = 0;
    #pragma omp parallel for
    for (int i = 0; i < omp_get_num_threads(); i++) {
      bbsint q, p = *p1, r;
      do {
        q = csrand((((bbsint) 1) << (N_BITS / 2 - 2)) - N_BITS, N_BITS / 2 - 2);
        q |= 0b11; r = 2 * q + 1;
      } while (!found && (!is_prime_low(r) || !is_prime_high(r, ROUNDS)
            || modexp_half(2, r - 1, r) != 1 || 2 * q + 1 == p));
      #pragma omp critical
      { if (!found) *p2 = 2 * q + 1, found = 1; }
    }
  }
#endif

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
    bbsint diff = b - a;
    az = ctz(diff);
    b = a < b ? a : b;
    a = diff & ((bbsint) 1 << (N_BITS - 1)) ? 1 + ~diff : diff;
    if (a == b) return a;
  }
  return b << shift;
}

// ---------------------------------------------------------------------------
//      Interface to the Blum Blum Shub generator.
// ---------------------------------------------------------------------------
typedef struct { bbsint pq, x, x0, c; int pos; } bbs_t;
static void bbs_new(bbs_t * bbs) {
  bbsint p, q;  generate_primes(&p, &q);
  bbs->pq = p * q;
  for (;;) {
    bbs->x = csrand(bbs->pq, ilog2(bbs->pq));
    if (bbs->x <= 1) continue;
    if (bbs->x % p != 0 && bbs->x % q != 0) break;
  }
  bbs->x0 = bbs->x;
  bbs->c = (p - 1) * (q - 1) / gcd(p - 1, q - 1);
  bbs->pos = 0;
}
static void bbs_step(bbs_t * bbs) {
  bbs2int sq = ((bbs2int) bbs->x) * bbs->x;
  bbs->x = sq % bbs->pq;
  bbs->pos++;
}
static bbsint modexp(bbsint base, bbsint e, bbsint mod) {
  bbsint r = 1;
  while (e) {
    if (e & 1)
      r = (((bbs2int) r) * base) % mod;
    base = (((bbs2int) base) * base) % mod;
    e >>= 1;
  }
  return r;
}
static void bbs_set(bbs_t * bbs, unsigned i) {
  bbsint arg = modexp(2, i, bbs->c);
  bbs->x = modexp(bbs->x0, arg, bbs->pq);
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
static void bbs_nextbytes(bbs_t * bbs, void * bp, size_t len) {
  uint8_t * buf = bp;
  for (size_t i = 0; i < len; i++) {
    uint8_t r = 0;
    for (int i = 8; i != 0; --i) {
      bbs_step(bbs); r = (r << 1) | (bbs->x & 1);
    }
    buf[i] = r;
  }
}

// ---------------------------------------------------------------------------
//      CLI stub. By default, the program will output
//      an infinite stream of random numbers to stdout (64-bit,
//      native endian). If changed, it displays an experiment.
// ---------------------------------------------------------------------------
#if 0
int main(void) {
  init_secrandom();  populate_barrett_cache();
  bbs_t bbs;  bbs_new(&bbs);
  for (;;) {
    uint64_t r = bbs_next64(&bbs);
    fwrite(&r, 1, 8, stdout);
  }
}
#else
int main(void) {
  init_secrandom();  populate_barrett_cache();
  bbs_t bbs;  bbs_new(&bbs);
  uint8_t buf[64];
  printf("Current position: %d\n", bbs.pos);
  printf("Probing 64 bytes of data: ");
  bbs_nextbytes(&bbs, buf, 64);
  for (int i = 0; i < 64; i++)
    printf("%02x", buf[i]);
  printf("\n");
  printf("Current position: %d\n", bbs.pos);
  printf("Probing another 64 bytes of data: ");
  bbs_nextbytes(&bbs, buf, 64);
  for (int i = 0; i < 64; i++)
    printf("%02x", buf[i]);
  printf("\n");
  printf("Rewinding to position 512.\n");
  bbs_set(&bbs, 512);
  printf("Current position: %d\n", bbs.pos);
  printf("Probing 64 bytes of data: ");
  bbs_nextbytes(&bbs, buf, 64);
  for (int i = 0; i < 64; i++)
    printf("%02x", buf[i]);
  printf("\n");
}
#endif
