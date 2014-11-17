
#include <stdio.h>
#include <inttypes.h>
#include "ip-tree.h"

void func (void * val, uint8_t * key, int k_len ) {
  printf("%u.%u.%u.%u:",key[0],key[1],key[2],key[3]);
  printf("%ld\n",(long)val);
}

void main(void) {

  ipt * t = create();

  char address [4] = {3, 4, 5, 6};
  char address2 [4] = {3, 4, 8, 6};

  printf("%ld\n",ipt_add(t,address,4,30,1));
  printf("%ld\n",ipt_add(t,address,4,20,0));
  printf("%ld\n",ipt_add(t,address2,4,30,1));
  printf("%ld\n",ipt_add(t,address2,4,20,0));

  char key[4];
  ipt_iter(t,4,4,key, func);
}
