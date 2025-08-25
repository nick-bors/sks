
typedef struct {
	void (*task)(void*);
	void *arg;
} Job;

typedef struct {
	int num_threads;
	int active;

} ThreadPool;
