
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

typedef void* ipt;
long ipt_add(ipt* t, uint8_t * key, int len, int amount, char ins);
void ipt_iter(ipt * t, int levels, int k_len, char * k, void(f)(void*,uint8_t*,int));
ipt * create();
