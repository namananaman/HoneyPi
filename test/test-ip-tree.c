
#include <stdio.h>
#include "ip-tree.h"


void main(void) {

  ipt * t = create();

  char address [4] = {3, 4, 5, 6};
  char address2 [4] = {3, 4, 8, 6};

  printf("%ld\n",ipt_add(t,address,4,30));
  printf("%ld\n",ipt_add(t,address,4,30));
  printf("%ld\n",ipt_add(t,address2,4,30));
  printf("%ld\n",ipt_add(t,address2,4,30));

}
