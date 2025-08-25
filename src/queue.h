#ifndef SKS_QUEUE_H
#define SKS_QUEUE_H

#include <pthread.h>

typedef struct Node {
	void (*task)(void *);
	void *arg;

	struct Node *next;
} Node;


typedef struct {
	size_t max;
	Node *head;
	Node *tail;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t *threads;
	int stop;
} Pool;

Pool *pool_create(size_t);
void  pool_destroy(Pool *);
void  pool_job(Pool *, void (*)(void *), void *);

#endif  // SKS_QUEUE_H
