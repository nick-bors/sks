#include <git2/repository.h>
#include <git2/tree.h>
#include <git2/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <git2.h>

#include "uri.h"
#include "zbase32.h"

#define BUFFER_SIZE 1024
#define MAX_CERTS 10

#define HEADER_SIZE       (1 << 9)  // 512b. More than enough to store the HTTP header.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define RESPONSE_SIZE     (1 << 15) // 32kb. Enough for ~6 large RSA keys or ~12 small ECC keys.

#define LEN(x)    (sizeof(x)/sizeof((x)[0]))
#define MIN(a,b)  ((a) < (b) ? (a) : (b))

void  die(const char *, ...);
void *handle(void *);
void  get(int, char *);
int   main(int, char *[]);

int skip_wellknown(const char *, const char *);

void handle_hashed_user(int, Uri *, int);
void handle_submission_address(int, const char *);
void handle_policy(int);

void *handle_authget   (int, char *);
void *handle_get       (int, char *);
void *handle_prefixlog (int, char *);
void *handle_vfpget    (int, char *);
void *handle_kidget    (int, char *);
void *handle_hget      (int, char *);
void *handle_index     (int, char *);
void *handle_vindex    (int, char *);
void *handle_stats     (int, char *);

/*
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
*/


typedef struct {
	git_repository *repo;
} State;

static State state;

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

void bad_request(int clientfd) {
	static const char reply[] = "HTTP/1.1 400 Bad Request\r\n"
							    "Content-Length: 0\r\n"
							    "\r\n";

	send(clientfd, reply, sizeof(reply) - 1, 0);
}

void internal_server_error(int clientfd) {
	char *reply = "HTTP/1.1 500 Internal Server Error\r\n"
				  "Content-Length: 0\r\n"
				  "\r\n";

	send(clientfd, reply, strlen(reply), 0);
}

void not_found(int clientfd) {
	char *reply = "HTTP/1.1 404 Not Found\r\n"
				  "Content-Length: 0\r\n"
				  "\r\n";

	send(clientfd, reply, strlen(reply), 0);
}

int skip_wellknown(const char *resource, const char *domain) {
    static const char prefix[]   = "/.well-known/openpgpkey/";
	static const int  prefix_len = sizeof(prefix) - 1;

	/* Simple:   /.well-known/openpgpkey/ */
	if (strncmp(resource, prefix, prefix_len) != 0)
		return -1;

    const char *post = resource + prefix_len;
	size_t domain_len = strlen(domain);

	if (strncasecmp(domain, post, strlen(domain)) == 0
		&& post[domain_len] == '/') {
		post += domain_len + 1;	
	}

	return post - resource;
}

void get(int clientfd, char *cursor) {
	char *rawuri = cursor;
	cursor = strchr(cursor, ' ');
	*cursor++ = '\0';

	Uri *uri = malloc(sizeof(Uri));
	int e = parse_uri(uri, rawuri);
	if (e < 0) {
		bad_request(clientfd);
		return;
	}

	const char *domain = "example.com";

	int offset = skip_wellknown(uri->resource, domain);
	if (offset < 0) {
		bad_request(clientfd);
		return;
	}

	const char *suffix = uri->resource + offset;

    static const char hu_suffix[]   = "hu/";
	static const int  hu_suffix_len = sizeof(hu_suffix) - 1;

    static const char policy_suffix[]   = "policy";
	static const int  policy_suffix_len = sizeof(policy_suffix) - 1;

    static const char sub_suffix[]   = "submission-address";
	static const int  sub_suffix_len = sizeof(sub_suffix) - 1;

	if (strncmp(suffix, hu_suffix, hu_suffix_len) == 0) {
		handle_hashed_user(clientfd, uri, offset + hu_suffix_len);
		return;
	}

	if (strncmp(suffix, policy_suffix, policy_suffix_len) == 0) {
		handle_policy(clientfd);
		return;
	}

	if (strncmp(suffix, sub_suffix, sub_suffix_len) == 0) {
		handle_submission_address(clientfd, domain);
		return;
	}

	not_found(clientfd);
	return;
}

void handle_policy(int clientfd) {
	char *reply = "HTTP/1.1 200 OK\r\n"
				  "Content-Type: text/plain; charset=UTF-8\r\n"
				  "Content-Length: 22\r\n"
				  "\r\n"
				  "protocol-version: 20\r\n";

	send(clientfd, reply, strlen(reply), 0);
}

void handle_submission_address(int clientfd, const char *domain) {
	static const char local[] = "openpgpkey@";
	char *body = malloc(strlen(domain) + sizeof(local));


	memcpy(body, local, sizeof(local));
	strcat(body, domain);

	if(strlen(body) > 256) {
		bad_request(clientfd);
		return;
	}
	// fixed header = 108
	// max email length 256 hence Content-Length = 3
	// null = 1
	// total: 112
	char *head = malloc(112);
	
	sprintf(head,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: %zu\r\n"
		"Cache-Control: max-age=86400\r\n"
		"\r\n",
		strlen(body));

	send(clientfd, head, strlen(head), 0);
	send(clientfd, body, strlen(body), 0);
}

void handle_hashed_user(int clientfd, Uri *uri, int offset) {
	const char *hash = uri->resource + offset;
	printf("hash is: %s\n", hash);
	if (strlen(hash) != 32) {
		printf("bad REQ, hashlen expected 32, got %zu\n", strlen(hash));
		bad_request(clientfd);
		return;
	}

	if(!is_zbase32_chars(hash)) {
		printf("hash is not zbase32 alphabet\n");
		bad_request(clientfd);
		return;
	}

	git_repository *repo = state.repo;
	git_oid oid;
	git_commit *commit;
	git_tree *tree = NULL;
	git_tree_entry *tree_entry = NULL;
	int err;

	err = git_reference_name_to_id(&oid, repo, "HEAD");
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't get HEAD reference %d/%d: %s\n", err, e->klass, e->message);
		internal_server_error(clientfd);
		return;
	}

	err = git_commit_lookup(&commit, repo, &oid);
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't look up object id in git database %d/%d: %s\n", err, e->klass, e->message);
		internal_server_error(clientfd);
		return;
	}

	err = git_commit_tree(&tree, commit);
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't get tree for commit %d/%d: %s\n", err, e->klass, e->message);
		internal_server_error(clientfd);
		return;
	}

	// Split into directories by starting hash letter
	char dirstr[2] = {hash[0], '\0'};

	err = git_tree_entry_bypath(&tree_entry, tree, dirstr);
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't find \"%s/\" subdirectory %d/%d: %s\n", dirstr, err, e->klass, e->message);
		not_found(clientfd);
		return;
	}

	if (git_tree_entry_type(tree_entry) != GIT_OBJECT_TREE) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Expected a directory \"%s/\", not a file %d/%d: %s\n", dirstr, err, e->klass, e->message);
		internal_server_error(clientfd);
		return;
	}

	git_tree *dir = NULL;
	err = git_tree_lookup(&dir, repo, git_tree_entry_id(tree_entry));
	if (err < 0) {
		const git_error *e = git_error_last();
		fprintf(stderr, "Couldn't look-up \"%s/\"tree %d/%d: %s\n", dirstr, err, e->klass, e->message);
		internal_server_error(clientfd);
		return;
	}


	char *header;
	char *body;
	size_t body_len = 0;

	for (size_t i = 0; i < git_tree_entrycount(dir); i++) {
		const git_tree_entry *e = git_tree_entry_byindex(dir, i);

		if (!e)
			continue;

		const char *name = git_tree_entry_name(e);
		const git_oid *oid = git_tree_entry_id(e);

		printf("hash: %s\n", hash);
		printf("curr: %s\n", name);
		if (strncmp(hash, name, 32) == 0) {
			printf("Matches! %s\n", name);

			git_blob *blob;
			err = git_blob_lookup(&blob, repo, oid);
			if (err < 0) {
				const git_error *e = git_error_last();
				fprintf(stderr, "Couldn't read blob %s %d/%d: %s\n", name, err, e->klass, e->message);
				continue;
			}

			body_len = git_blob_rawsize(blob);
			body = malloc(body_len);

			memcpy(body, git_blob_rawcontent(blob), body_len);

			git_blob_free(blob);
			header = malloc(512);
			snprintf(
				header,
				512,
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/octet-stream\r\n"
				"Content-Length: %zu\r\n"
				"\r\n",
				body_len
			);

			send(clientfd, header, strlen(header), 0);
			send(clientfd, body, body_len, 0);
			free(header);
			free(body);
			free(uri);
			return;
		}
	}



	// TODO: implement
	/* Advanced: /.well-known/openpgpkey/example.com/hu/ */

	not_found(clientfd);
	free(uri);
}

/*
void *handle_authget(int clientfd, char *cursor) {
	printf("handling authget..\n");
	return NULL;
}

void *handle_get(int clientfd, char *cursor) {
	printf("handling get..\n");

		printf("%s\n", cursor);

	// send(clientfd, header, strlen(header), 0);
	// send(clientfd, body, body_len, 0);

	return NULL;
}

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
