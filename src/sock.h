#ifndef SWS_SOCK_H
#define SWS_SOCK_H

#include <sys/types.h>

int get_in_sock(const char *, const char*);
int get_unix_sock(const char *, uid_t, gid_t);

#endif  // SWS_SOCK_H
