#ifndef HASH_H_
#define HASH_H_
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct hashmap {
  struct queue * buckets;
  int32_t key_len;
  int32_t(*hash_func)(uint8_t*);
  int32_t buffer_size; // the size of the hashtable (number of buckets)
  int32_t entries;
};

/* initializes the hashtable */
void hashtable_initialize(struct hashmap * self,int32_t size, int32_t(*hash_func)(uint8_t*), int key_len);

int32_t default_hash(uint8_t *);

/* doubles the size of the hashtable */
void hashtable_resize(struct hashmap *self);

/* adds a new entry to the hashtable */
void hashtable_add(struct hashmap *self, uint8_t * key, void* value);

/* returns the index of the given key, -1 if not found */
int hashtable_find(struct hashmap *self, uint8_t * key);

/* increments the value of a given key, -1 if not found */
void hashtable_increment(struct hashmap *self, uint8_t * key, int value);

/* deletes an entry from the hashtable */
void hashtable_delete(struct hashmap *self, uint8_t * key);

/* gets a value from the hashtable given a key, -1 if not found */
void * hashtable_get(struct hashmap *self, uint8_t * key);

/* prints out the statistics of the hashtable */
void hashtable_stats(struct hashmap *self);

/* prints out the contents of the hashtable */
void hashtable_iter(struct hashmap *self, void(*iter_func)(void *, uint8_t *, int32_t));

/* returns the ith entry int the hash table depending on hash */
struct hash_pair *hashtable_gethashpair(struct hashmap *self, uint8_t * i);

#endif
