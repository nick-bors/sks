#include <pthread.h>
#include <stdlib.h>

#include "queue.h"
#include "util.h"

static void *worker_entry(void *);
static Node *dequeue(Pool *);

Pool *
pool_create(size_t nthreads)
{
	Pool *p;
	int i;

	if (!(p = calloc(1, sizeof(Pool))))
		die("calloc:");

	if (!(p->max = i = nthreads))
		return NULL;

	if (!(p->threads = calloc(p->max, sizeof(pthread_t))))
		die("calloc:");

	p->head = NULL;
	p->tail = NULL;
	pthread_mutex_init(&p->mutex, NULL);
	pthread_cond_init(&p->cond, NULL);

	while (i--) {
		if (pthread_create(&p->threads[i], NULL, worker_entry, p))
			die("pthread_create:");
	}

	return p;
}

void
pool_destroy(Pool *p)
{
	int i;

	if (!p)
		return;

	pthread_mutex_lock(&p->mutex);
	p->stop = 1;
	pthread_cond_broadcast(&p->cond);
	pthread_mutex_unlock(&p->mutex);

	for (i = 0; i < p->max; i++) {
		pthread_join(p->threads[i], NULL);
	}

	pthread_mutex_destroy(&p->mutex);
	pthread_cond_destroy(&p->cond);

	Node *tmp;
	for (; p->head; p->head = tmp) {
		tmp = p->head->next;
		free(p->head);
	}

	free(p->threads);
	free(p);
}

void
pool_job(Pool *p, void (*task)(void *), void *data)
{
	if (!p || p->stop)
		return;

	Node *new = malloc(sizeof(Node));
	new->task = task;
	new->arg = data;
 	
	pthread_mutex_lock(&p->mutex);

	new->next = NULL;
	if (p->tail) {
		p->tail->next = new;
		p->tail = new;
	} else {
		p->head = p->tail = new;
	}

	pthread_cond_signal(&p->cond);
	pthread_mutex_unlock(&p->mutex);
}

Node *
dequeue(Pool *p)
{
	if (!p || !p->head)	
		return NULL;

	Node *temp = p->head;
	p->head = p->head->next;

	if (!p->head)
		p->tail = NULL;

	/* user must free */
	return temp;
}

void *
worker_entry(void *arg)
{
	Pool *p = (Pool*)arg;

	for (;;) {
		Node *n = NULL;

		pthread_mutex_lock(&p->mutex);

		while (!p->stop && !(n = dequeue(p)))
			pthread_cond_wait(&p->cond, &p->mutex);

		pthread_mutex_unlock(&p->mutex);


		if (!n)
			break;

		(n->task)(n->arg);
		free(n);
	}
	return NULL;
}
