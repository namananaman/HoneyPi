#include "hashtable.h"

void iter(uint8_t * key, void * value, int32_t key_len) {
  int i;
  for (i= 0; i < key_len; i++) {
    printf("%02x",key[i]);
  }
  printf(":%ld\n", (long)value);
}

int main(void) {

  hashtable_t a = hashtable_create();


  hashtable_initialize(a, 200, default_hash, 4);

  uint8_t key[4] = {1,2,3,4};
  hashtable_add(a,key,(void*)5);


  printf("val = %ld\n", (long)hashtable_get(a, key));
  hashtable_iter(a,iter);

  hashtable_delete(a,key);

  return 0;
}
