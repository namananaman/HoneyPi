#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha256.h"
int main(void) {

  srand(time(NULL));
  unsigned char digest[256];

  unsigned char data[1200];
  int i;
  for (i = 0; i < 1200; i++) {
    data[i] = (char)rand();
  }

  SHA256(data, 1200 ,&digest);

  printf("done\n");

}
