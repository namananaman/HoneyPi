#include <stdio.h>
#include <stdio.h>
#include <sys/time.h>
#include <inttypes.h>
uint64_t djb2(unsigned char *str, uint64_t n)
{
  uint64_t hash = 5381;
  uint64_t c,i;
  for (i = 0; i < n; i++) {
    c = str[i];
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}

int main(void) {
  volatile unsigned char bytes[8192];
  volatile uint64_t ret;
  uint64_t perf[5];
  for (uint64_t i = 0; i < 8192; i++) {
    bytes[i] = rand() %0xff;
  }
  struct timeval t0, t1;
  for (uint64_t i = 0; i < 5; i++) {
    uint64_t j = 1 << ((i<<1) + 4);
    printf ("hashing blocks of size %llu\n",j);
    gettimeofday(&t0, 0);
    uint64_t num = 0;
    while(1) {
      ret = djb2(bytes, j);
      gettimeofday(&t1, 0);
      long elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec;
      if (elapsed > 4*1000000) break;
      num++;
    }
    perf[i] = num * j * 8 / 4000000;
  }
  for (uint64_t i = 0; i < 5; i++) {
    printf("%llu Mbps ",perf[i]);
  }
  printf("\n");
  return 0;
}
