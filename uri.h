#ifndef SKS_URI_H
#define SKS_URI_H
#include <stdio.h>

typedef struct {
	const char *key;
	const char *value;
} QueryPair;

typedef struct {
	const char *resource;
	QueryPair *params;
	size_t params_count;
} Uri;

int parse_uri(Uri *, char *);
int skip_wellknown(const char *, const char *);

void print_uri(Uri *u);

#endif  // SKS_URI_H
