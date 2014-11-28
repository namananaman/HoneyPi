#include "hashtable.h"
#include "queue.h"
#include <string.h>


struct hp  * _get(struct hashmap * self, uint8_t * key);
void hashtable_add_nr(struct hashmap * self, uint8_t * key, void * value);
int find_bucket(struct hashmap * self, uint8_t * key);

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


struct hp {
  uint8_t * key;
  void * value;
  uint8_t valid;
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


void hashtable_initialize(struct hashmap * self,int32_t size, int32_t(*hash_func)(uint8_t*), int32_t key_len) {
  self->key_len = key_len;
  self->hash_func = hash_func;
  self->buffer_size = size;
  self->entries = 0;
  self->buckets = malloc(size * sizeof(struct queue));
  int i;
  for (i = 0; i < size; i++) {
    init_queue(&(self->buckets[i]));
  }
}



void hashtable_resize(struct hashmap * self) {
  // create new hashtable

  int new_buffer_size = (self->buffer_size < 1 ? 2: self->buffer_size << 1);

  struct hashmap new_map;
  hashtable_initialize(&new_map, new_buffer_size, self->hash_func, self->key_len);

  int i;
  // fill new table with old table entries
  for (i = 0; i < self->buffer_size; i++) {
    struct hp * pair;
    while (queue_dequeue(&(self->buckets[i]),(void**)&pair)!=-1) {
      hashtable_add_nr(&new_map, pair->key, pair->value);
      free(pair->key);
      free(pair);
    }
  }

  if (self->buffer_size > 0) free(self->buckets);
  self->buckets = new_map.buckets;
  self->buffer_size = new_buffer_size;
  self->entries = new_map.entries;
}

void hashtable_add(struct hashmap * self, uint8_t * key, void * value) {
  // check inputs
  if(!self){return;}
  if(self->buffer_size < 1 || ((((double)(self->entries+1))/((double)self->buffer_size)) > 0.5)) {
    hashtable_resize(self);
  }
  hashtable_add_nr(self,key,value);
}
void hashtable_add_nr(struct hashmap * self, uint8_t * key, void * value) {


  struct hp * op = _get(self,key);
  if (!op) {
    struct hp * np= malloc(sizeof (struct hp));
    np->key = malloc(self->key_len);
    memcpy(np->key,key,self->key_len);
    np->value = value;
    np->valid = 1;
    // find place to put the value
    queue_t bucket = &self->buckets[find_bucket(self,key)];
    queue_append(bucket, (void*)np);
    self->entries += 1;
  } else {
    op->value = value;
  }
}

int find_bucket(struct hashmap * self, uint8_t * key) {
  return self->hash_func(key)%self->buffer_size;
}

void hashtable_increment(struct hashmap * self, uint8_t * key, int amount) {
  struct hp *pair =  _get(self,key);
  if (pair) {
    pair->value+=amount;
  }
}

struct key_pair {
  int32_t len;
  uint8_t * key;
  struct hp * pair;
};

int matches_key(void * keyp, void * key2) {
  struct hp * pair = (struct hp *)key2;
  struct key_pair * k = keyp;
  if (compare(k->key, pair->key, k->len)) {
    k->pair = key2;
  }
  return 0;
}

struct hp * find_key(queue_t q, uint8_t * key, int len){

  struct key_pair arg = {
    .len = len,
    .key = key,
    .pair = NULL,
  };
  queue_iterate(q,matches_key, (void*)&arg);

  return arg.pair;

}
struct hp  * _get(struct hashmap * self, uint8_t * key) {
  int index = find_bucket(self,key);
  return find_key(&(self->buckets[index]), key, self->key_len);
}

/* Returns the value of the given key, -1 if key not found */
void * hashtable_get(struct hashmap * self, uint8_t * key) {
  struct hp * pair = _get(self,key);

  if (pair) {
    return pair->value;
  } else {
    return NULL;
  }

}

void hashtable_delete(struct hashmap * self, uint8_t * key) {
  int index = find_bucket(self,key);
  struct hp * pair = find_key(&(self->buckets[index]), key, self->key_len);
  if(!queue_delete(&(self->buckets[index]), (void**)&pair)) {
    self->entries--;
  }
}

struct iter_arg {
  void(*iter_func)(void*,uint8_t*,int32_t);
  int32_t key_len;
};

int __iter(void * argp, void * pairp) {
  struct iter_arg * arg = argp;
  struct hp * pair = pairp;
  arg->iter_func(pair->value, pair->key, arg->key_len);
  return 0;
}

void hashtable_iter(struct hashmap * self, void(*iter_func)(void *,uint8_t*, int32_t key_len)) {

  struct iter_arg arg = {
    .iter_func = iter_func,
    .key_len = self->key_len,
  };

  if (self->buffer_size > 0) {
    int i;
    for(i = 0; i < self->buffer_size; i++) {
      if (queue_length(&(self->buckets[i])) >0) {
          queue_iterate(&(self->buckets[i]),__iter,&arg);
        }
    }
  }
  return;
}



