#include "hashtable.h"
#include <string.h>
struct hashtable {
  hash_pair_t buffer;     // pointer to allocated memory
  int32_t key_len;
  int32_t(*hash_func)(uint8_t*);
  int buffer_size; // the size of the hashtable
  int entries;  // the number of non-null buckets
};

struct hash_pair {
  uint8_t * key;
  void * value;
  char valid;
};

char compare(uint8_t * s1, uint8_t * s2, int32_t n) {
  int i;
  for (i= 0; i < n; i++) {
    if (s1[i] != s2[i]) {
      return 0;
    }
  }
  return 1;
}

int32_t default_hash(uint8_t * key) {
  int32_t hash = 5381;
  int length = 4;
  int i = 0;
  while(length > 0) {
    hash = ((hash << 5) + hash) + key[i++];
    length--;
  }
  return hash;
}

void hashtable_initialize(hashtable_t self,int32_t size, int32_t(*hash_func)(uint8_t*), int32_t key_len) {
  int i;
  self->buffer = (hash_pair_t )malloc(size*sizeof(struct hash_pair));;
  for(i = 0; i < size; i++) self->buffer[i].valid = 0;
  self->buffer_size =size;
  self->entries = 0;
  self->hash_func = hash_func;
  self->key_len = key_len;
}

hashtable_t hashtable_create() {
  return (hashtable_t)malloc(sizeof(struct hashtable));
}

void hashtable_resize(hashtable_t self) {
  // create new hashtable


  int new_buffer_size = (self->buffer_size < 1 ? 2: self->buffer_size << 1);
  struct hash_pair cur_pair;
  int i;
  int j;
  int index = 0;
  hash_pair_t new_buffer = (hash_pair_t )malloc(new_buffer_size*sizeof(struct hash_pair));

  for (j = 0; j < new_buffer_size; j++) {
    new_buffer[j].valid = 0;
  }
  // fill new table with old table entries
  for (i = 0; i < self->buffer_size; i++) {
    cur_pair = self->buffer[i];
    if (cur_pair.valid == 0) continue;
    index = (self->hash_func(self->buffer[i].key)%new_buffer_size);
    while(new_buffer[index].valid == 1) {
      index++;
      index = index % new_buffer_size;
    }
    new_buffer[index] = cur_pair;

  }
  index = 0;
  if (self->buffer_size > 0) free(self->buffer);
  self->buffer = new_buffer;
  self->buffer_size = new_buffer_size;
}

void hashtable_add(hashtable_t self, uint8_t * key, void * value) {
  struct hash_pair new_hash_pair;
  int index = 0;
  // check inputs
  if(!self){return;}
  if(self->buffer_size < 1 || ((((double)(self->entries+1))/((double)self->buffer_size)) > 0.5)) {
    hashtable_resize(self);
  }
  new_hash_pair.key = malloc(self->key_len);
  memcpy(new_hash_pair.key,key,self->key_len);
  new_hash_pair.value = value;
  new_hash_pair.valid = 1;
  // find place to put the value
  index = self->hash_func(new_hash_pair.key)%self->buffer_size;
  while(self->buffer[index].valid == 1) {
    index++;
    index = index % self->buffer_size;
  }
  self->buffer[index] = new_hash_pair;
  self->entries += 1;
}

int hashtable_find(hashtable_t self, uint8_t * key) {
  int i, index;
  if (self->buffer_size <= 0 || self->entries <= 0) return -1;
  index = self->hash_func(key)%self->buffer_size;
  for (i = 0; i < self->buffer_size; i++) {
    struct hash_pair * cur_pair = &self->buffer[index];
    if (cur_pair->valid == 0) break;
    if (compare(key,cur_pair->key,self->key_len)) {
      return index;
    }
    index = (index + 1)%self->buffer_size;
  }
  return -1;
}

int32_t hashtable_increment(hashtable_t self, uint8_t * key) {
  int index = hashtable_find(self, key);
  if (index >= 0) {
    self->buffer[index].value++;
    return 0;
  } else {
    return -1;
  }
}


/* Returns the value of the given key, -1 if key not found */
void * hashtable_get(hashtable_t self, uint8_t * key) {
  int index = hashtable_find(self, key);
  if (index >= 0) return self->buffer[index].value;
  else return (NULL);
}

void hashtable_delete(hashtable_t self, uint8_t * key) {
  int index = hashtable_find(self, key);
  if (index >= 0) {
    self->buffer[index].valid = 0;
    free(self->buffer[index].key);
    self->entries -= 1;
  }
  return;
}

void hashtable_stats(hashtable_t self) {
  int length = self->entries;
  int N = self->buffer_size;
  printf("length = %d, N = %d\n", length, N);
  return;
}

void hashtable_iter(hashtable_t self, void(*iter_func)(void *,uint8_t*, int32_t key_len)) {
  if (self->buffer_size > 0) {
    int i;
    for(i = 0; i < self->buffer_size; i++) {
      if (self->buffer[i].valid == 1) {
        iter_func(self->buffer[i].value, self->buffer[i].key, self->key_len);
      }
    }
  }
  return;
}

hash_pair_t hashtable_gethashpair(hashtable_t self, uint8_t * index) {
  int i;
  for (i = 0; i < self->buffer_size; i++) {
    if (self->buffer[i].valid == 1) {
      if (index == 0) return &self->buffer[i];
      index--;
    }
  }
  return (hash_pair_t )0;
}


