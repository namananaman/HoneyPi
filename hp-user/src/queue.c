/*
 * Generic queue implementation.
 *
 */
#include "queue.h"
#include <stdlib.h>
#include <stdio.h>


struct node {
    void * datum;
    node_t next_node;
};

/*
 * Return an empty queue.
 */
queue_t
queue_new() {
  queue_t q = (queue_t)malloc(sizeof(struct queue));
  if (!q) {printf("couldn't allocate new queue\n"); return NULL;}
  q->head = NULL;
  q->tail = NULL;
  q->size = 0;
  return q;
}

void init_queue(queue_t q) {
  q->head = NULL;
  q->tail = NULL;
  q->size = 0;
}

node_t
node_new(void* datum) {
  node_t new_node = (node_t)malloc(sizeof(struct node));
  if(!new_node) {printf("couldn't allocate node\n"); return NULL;}
  new_node->datum = datum;
  new_node->next_node = NULL;
  return new_node;
}
/*
 * Prepend a void* to a queue (both specifed as parameters).  Return
 * 0 (success) or -1 (failure).
 */
int
queue_prepend(queue_t queue, void* item) {
    if(queue) {
      node_t head = queue->head;
      node_t new_node = node_new(item);
      if (!new_node) return -1;
      queue->size++;
      if (head == NULL) {
        queue->head = new_node;
        queue->tail = new_node;
        return 0;
      } else {
        queue->head = new_node;
        new_node->next_node=head;
        return 0;
      }
  } else return -1;
}

/*
 * Append a void* to a queue (both specifed as parameters). Return
 * 0 (success) or -1 (failure).
 */
int
queue_append(queue_t queue, void* item) {
    if(queue){
      node_t new_node = node_new(item);
      if (!new_node) return -1;
      queue->size++;
      if(queue->head == NULL) {
        queue->head = new_node;
        queue->tail = new_node;
      } else {
        queue->tail->next_node = new_node;
        queue->tail = new_node;
      }
      return 0;
    } else return -1;
}

int queue_insert_in_order(queue_t queue, PFany comp, void * item){
  node_t node;
  node_t new_node = node_new(item);
  if (queue) {
    if (!queue->head || comp(queue->head->datum,item) >= 0) {
      new_node->next_node = queue->head;
      queue->head = new_node;
      queue->size+=1;
      return 0;
    }
    node = queue->head;
    while(node) {
        if(comp(node->datum,item) == 0) {
          new_node->next_node = node->next_node;
          node->next_node = new_node;
          queue->size+=1;
          return 0;
        } else if (comp(node->datum,item) < 0 && !node->next_node){
          node->next_node = new_node;
          new_node->next_node = NULL;
          queue->size+=1;
          return 0;
        } else if (comp(node->datum,item) < 0 && comp(node->next_node->datum, item) >= 0) {
          new_node->next_node = node->next_node;
          node->next_node = new_node;
          queue->size+=1;
          return 0;
          break;
        } else {
          node =node->next_node;
        }
      }
    }
    return 0;
}


void
free_node(node_t node) {
  free(node);
}

/*
 * Dequeue and return the first void* from the queue or NULL if queue
 * is empty.  Return 0 (success) or -1 (failure).
 */
int
queue_dequeue(queue_t queue, void** item) {
    if(queue) {
      node_t head;
      if (queue->size>0 && queue->head) {
        *item = queue->head->datum;
        head = queue->head;
        queue->head = queue->head->next_node;
        free_node(head);
        queue->size--;
        if(queue->size == 1) queue->tail = queue->head;
        return 0;
      }
      *item = NULL;
      return -1;
    } else return -1;
}

/*
 * Iterate the function parameter over each element in the queue.  The
 * additional void* argument is passed to the function as its first
 * argument and the queue element is the second.  Return 0 (success)
 * or -1 (failure).
 */
int
queue_iterate(queue_t queue, PFany f, void* item) {
  node_t node;
  int ret = 0;
  if (queue && queue->size > 0) {
    node = queue->head;
    while(node) {
      ret = ret | f(item,node->datum);
      node = node->next_node;
    }
    return ret;
  } else return 0;
}

/*
 * Free the queue and return 0 (success) or -1 (failure).
 */
int
queue_free (queue_t queue) {
  if (queue) {
  node_t node = NULL;
  node_t next = NULL;
  node = queue->head;
  while(node) {
    next = node->next_node;
    free_node(node);
    node = next;
  }
  free(queue);
  return 0;
  } else return -1;
}

/*
 * Return the number of items in the queue.
 */
int
queue_length(queue_t queue) {
  if (queue) return queue->size;
  else return -1;
}

/*
 * Delete the specified item from the given queue.
 * Return -1 on error.
 */
int
queue_delete(queue_t queue, void** item) {
  node_t current_node = NULL;
  node_t prev_node = NULL;
  if (queue && queue->size > 0) {
    current_node = queue->head;
    while(current_node) {
      if(current_node->datum == *item) {
        if(current_node == queue->head){
            queue->head = current_node->next_node;
        } else {
          // there will be a prev node if current_node != head
          prev_node->next_node = current_node->next_node;
        }
        if(current_node == queue->tail) queue->tail = prev_node;
        free_node(current_node);
        return 0;
      }
      prev_node = current_node;
      current_node = current_node->next_node;
    }
    return -1;
  }
  else return -1;
}


