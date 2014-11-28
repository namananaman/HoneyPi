#include "hashtable.h"

void iter(void * value, uint8_t * key, int32_t key_len) {
  int i;
  for (i= 0; i < key_len; i++) {
    printf("%02x",key[i]);
  }
  printf(":%ld\n", (long)value);
}

int main(void) {
  struct hashmap aa;
  struct hashmap *a= &aa;



  hashtable_initialize(a, 200, default_hash, 4);

  uint8_t key[4] = {1,2,3,4};
  int i;
  for (i= 0; i < 10; i++) {
    key[0] = i;
    hashtable_add(a,key,(void*)5);

  }

  hashtable_iter(a,iter);
  printf("deleting\n");

  for (i= 0; i < 5; i++) {
    key[0] = i;
    hashtable_delete(a,key);
  }

  hashtable_iter(a,iter);
  return 0;
}
