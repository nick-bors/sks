#include <git2/repository.h>
#include <git2/tree.h>
#include <git2/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <git2.h>

#define BUFFER_SIZE 1024
#define MAX_CERTS 10

#define HEADER_SIZE       (1 << 9)  // 512b. More than enough to store the HTTP header.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define RESPONSE_SIZE     (1 << 15) // 32kb. Enough for ~6 large RSA keys or ~12 small ECC keys.

#define LEN(x)    (sizeof(x)/sizeof((x)[0]))
#define MIN(a,b)  ((a) < (b) ? (a) : (b))

void die(const char *, ...);
void *handle(void *);
void get(int, char *);
int main(int, char *[]);

void *handle_authget   (int, char *);
void *handle_get       (int, char *);
void *handle_prefixlog (int, char *);
void *handle_vfpget    (int, char *);
void *handle_kidget    (int, char *);
void *handle_hget      (int, char *);
void *handle_index     (int, char *);
void *handle_vindex    (int, char *);
void *handle_stats     (int, char *);

static struct {
	const char *op; void* (*handler)(int, char *);
} Handlers[] = {
	// {"authget", handle_authget},
	{"get", handle_get},
	// {"prefixlog", handle_prefixlog},
	// {"vfpget", handle_vfpget},
	// {"kidget", handle_kidget},
	// {"hget", handle_hget},
	// {"index", handle_index},
	// {"vindex", handle_vindex},
	// {"stats", handle_stats},
};


typedef struct {
	git_repository *repo;
} State;

static State state;
static pthread_mutex_t repo_write_lock = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char *argv[])
{
	git_libgit2_init();

	int error = git_repository_open_bare(&state.repo, "./test.git");
	if (error < 0) {
		const git_error *e = git_error_last();
		die("Error %d/%d: %s", error, e->klass, e->message);
	}

	if(argc < 2)
		die("more args");

	int16_t port;

	if((port = atoi(argv[1])) <= 0)
		die("couldn't string %s into a port no", argv[1]);

	port = htons(port);

	int sfd;
	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		die("unable to create socket");

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = port
	};

	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("unable to bind to socket");

	if (listen(sfd, 10) < 0)
		die("unable to listen on socket");

	for (;;) {
		struct sockaddr_in client;
		int *clientfd = malloc(sizeof(int));
		socklen_t client_len = sizeof(client);

		if ((*clientfd = accept(sfd, (struct sockaddr *)&client, &client_len)) < 0)
			continue;

		pthread_t thread;
		pthread_create(&thread, NULL, handle, clientfd);
		pthread_detach(thread);
	}

	git_repository_free(state.repo);
	git_libgit2_shutdown();
	return EXIT_SUCCESS;
}

void* handle(void *arg) {
	int clientfd = *(int *)arg;
	char *buffer = malloc(BUFFER_SIZE);

	ssize_t bytes = recv(clientfd, buffer, BUFFER_SIZE - 1, 0);

	if (bytes > 0) {
		buffer[bytes] = '\0';

		if(strncmp(buffer, "GET ", 4) == 0) {
			get(clientfd, buffer + 4);
		} /* else if (strncmp(buffer, "POST ", 5) == 0) {

		} */

	}

	close(clientfd);
	free(arg);
	free(buffer);
	return NULL;
}

void get(int clientfd, char *cursor) {
	if(strncmp(cursor, "/pks/v2/", 8) == 0) {
		cursor += 8;
	} else if(strncmp(cursor, "/pks/lookup?op=", 15) == 0) {
		cursor += 15;
	}

	size_t i;

	for(i = 0; i < LEN(Handlers); i++) {
		if (strncmp(Handlers[i].op, cursor, strlen(Handlers[i].op)) == 0) {
			Handlers[i].handler(clientfd, cursor + strlen(Handlers[i].op) + 1);
			return;
		}
	}

	char *notfound = "HTTP/1.1 404 Not Found\r\n"
				  "Content-Length: 0\r\n"
				  "\r\n";

	send(clientfd, notfound, strlen(notfound), 0);
}

void *handle_authget(int clientfd, char *cursor) {
	printf("handling authget..\n");
	return NULL;
}

void *handle_get(int clientfd, char *cursor) {
	printf("handling get..\n");

		printf("%s\n", cursor);

	git_repository *repo = state.repo;
	git_oid oid;
	git_commit *commit;
	git_tree *tree = NULL;
	git_tree_entry *entry = NULL;
	int err;

	err = git_reference_name_to_id(&oid, repo, "HEAD");
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't get HEAD reference %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}

	err = git_commit_lookup(&commit, repo, &oid);
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't look up object id in git database %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}

	err = git_commit_tree(&tree, commit);
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't get tree for commit %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}


	err = git_tree_entry_bypath(&entry, tree, "keys");
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't get keys/ subdirectory %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}

	if (git_tree_entry_type(entry) != GIT_OBJECT_TREE) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Expected a directory \"keys/\", not a file %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}

	git_tree *keys_tree = NULL;
	err = git_tree_lookup(&keys_tree, repo, git_tree_entry_id(entry));
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't look-up keys tree %d/%d: %s\n", err, e->klass, e->message);
		return NULL;
	}

	char *body = malloc(RESPONSE_SIZE);
	char *body_cur = body;

	int matches = 0;
	for (size_t i = 0; i < git_tree_entrycount(keys_tree) && matches <= MAX_CERTS; i++) {
		const git_tree_entry *e = git_tree_entry_byindex(keys_tree, i);

		if (!e)
			continue;

		const char *name = git_tree_entry_name(e);
		const git_oid *oid = git_tree_entry_id(e);

		if (cursor[0] == '0' && cursor[1] == 'x')
			cursor += 2;

		size_t search_len = strchr(cursor, ' ') - cursor;

		printf("name: %s\n", name);
		printf("searh: %s\n", cursor);
		if (strncmp(cursor, name, MIN(search_len, strlen(name))) == 0) {
			matches++;
			printf("Matches! %s\n", name);

			git_blob *blob;
			err = git_blob_lookup(&blob, repo, oid);
			if (err < 0) {
				const git_error *e = git_error_last();
				fprintf(stderr, "Couldn't read blob %s %d/%d: %s\n", name, err, e->klass, e->message);
				return NULL;
			}

			size_t blob_size = git_blob_rawsize(blob);
			memcpy(body_cur, git_blob_rawcontent(blob), blob_size);
			body_cur += blob_size;

			git_blob_free(blob);
		}

	}

	if (body_cur == RESPONSE_SIZE - 1) {
		*body_cur = '\0';
	} else {
		body_cur++;
		*body_cur = '\0';
	}

	size_t body_len = body_cur - body;
	char *header = malloc(512);
	snprintf(header, 512, "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/pgp-keys\r\n"
                          "Content-Length: %zu\r\n"
		                  "\r\n", body_len);

	send(clientfd, header, strlen(header), 0);
	send(clientfd, body, body_len, 0);

	free(header);
	free(body);

	git_tree_free(keys_tree);
	git_tree_free(tree);
	git_commit_free(commit);
	git_tree_entry_free(entry);
	return NULL;
}
/*
void *handle_prefixlog(int clientfd, char *cursor) {
	printf("handling prefixlog..\n");
	return NULL;
}
void *handle_vfpget(int clientfd, char *cursor) {
	printf("handling vfpget..\n");
	return NULL;
}
void *handle_kidget(int clientfd, char *cursor) {
	printf("handling kidget..\n");
	return NULL;
}
void *handle_hget(int clientfd, char *cursor) {
	printf("handling hget..\n");
	return NULL;
}
void *handle_index(int clientfd, char *cursor) {
	printf("handling index..\n");
	return NULL;
}
void *handle_vindex(int clientfd, char *cursor) {
	printf("handling vindex..\n");
	return NULL;
}
void *handle_stats(int clientfd, char *cursor) {
	printf("handling stats..\n");
	return NULL;
}
*/


void die(const char *fmt, ...)
{
	va_list ap;
	int saved_errno;

	saved_errno = errno;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[0] && fmt[strlen(fmt)-1] == ':')
		fprintf(stderr, " %s", strerror(saved_errno));
	fputc('\n', stderr);

	exit(1);
}
