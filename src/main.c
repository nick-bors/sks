/* See LICENSE file for copyright and license details.
 *
 * simple key server (SKS) is designed to follow WKS and WKD specifications
 * (specifically, this ID draft-koch-openpgp-webkey-service-20). Unlike other
 * popular servers, SKS does not provide transport layer security (TLS) and
 * instead is designed to be used with a reverse proxy such as nginx, traefik
 * etc. This decision allows SKS to focus on simplicity, handling only the
 * storing, distributing, and submitting of OpenPGP keys.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <git2.h>
#include <git2/repository.h>
#include <git2/tree.h>
#include <git2/types.h>

#include "arg.h"
#include "uri.h"
#include "util.h"
#include "zbase32.h"
#include "sock.h"

/* macros */
#define BUFFER_SIZE 1024
#define MAX_CERTS 10

#define HEADER_SIZE       (1 << 9)  // 512b. More than enough to store the HTTP header.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define GET_REQUEST_SIZE  (1 << 10) // 1kb.  Should be enough on GET for all clients.
#define RESPONSE_SIZE     (1 << 15) // 32kb. Enough for ~6 large RSA keys or ~12 small ECC keys.

typedef struct {
	char *pidfile;
	char *lmtpsock;
	git_repository *repo;
} State;

/* function declarations */

static void sig_cleanup(int);
static void sig_reload(int);

static void  handle_sigs(void);
static void  usage(void);
static void *handle_http(void *);
static void  get(int, char *);
static void  handle_hashed_user(int, Uri *, int);
static void  handle_policy(int);
static void  handle_submission_address(int, const char *);

int main(int, char *[]);

/*
void *handle_authget   (int, char *);
void *handle_get       (int, char *);
void *handle_prefixlog (int, char *);
void *handle_vfpget    (int, char *);
void *handle_kidget    (int, char *);
void *handle_hget      (int, char *);
void *handle_index     (int, char *);
void *handle_vindex    (int, char *);
void *handle_stats     (int, char *);
*/


/* variables */
char *argv0;
static State state;

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

void
sig_cleanup(int sig)
{
	unlink(state.pidfile);
	unlink(state.lmtpsock);

	git_repository_free(state.repo);
	git_libgit2_shutdown();

	kill(0, sig);
	_exit(1);
}

void
sig_reload(int _sig)
{
	//TODO: invalidate cache/state
	return;
}

void
handle_sigs(void) {
	struct sigaction cleanup = {
		.sa_handler = sig_cleanup,
	};

	struct sigaction reload = {
		.sa_handler = sig_reload,
	};
	
	sigemptyset(&cleanup.sa_mask);
	sigemptyset(&reload.sa_mask);

	sigaction(SIGTERM, &cleanup, NULL);
	sigaction(SIGHUP,  &reload,  NULL);
	sigaction(SIGINT,  &cleanup, NULL);
	sigaction(SIGQUIT, &cleanup, NULL);
}

void
usage(void)
{
	die("Usage: %s [OPTIONS]\n"
	    "Options:\n"
            "  -p PORT_NUM   Port number to listen on (default: 11371)\n"
            "  -h HOSTNAME   Host/IP address to bind to (default: 0.0.0.0)\n"
            "  -U USER       User or UID user to run as (default: 'sks')\n"
            "  -G GROUP      Group or GID to run as (default: 'sks')\n"
	    "  -P PIDFILE    Location of the pidfile (default: '/run/sks/sks.pid')\n"
	    "  -L LMTPSOCK   Location of the LMTP socket to recieve mail on\n"
	    "                (default: '/run/sks/sks.sock')\n"
            "  -k KEYSDIR    Location of the keys git repository.\n"
            "                (default: '/var/lib/sks/keys.git')\n",
	    argv0);
}

void
write_pidfile(void)
{
	int pidfd = open(state.pidfile, O_WRONLY | O_CREAT, 0644);

	if (!pidfd)
		die("Couldn't open pidfile:");

	char buf[16];
	snprintf(buf, 16, "%ld\n", (long)getpid());
	if (write(pidfd, buf, strlen(buf)) < 0)
		die("write:");
}

/* function implementations */
int
main(int argc, char *argv[])
{
	int cfd, httpfd, lmtpfd;
	char *port = "11371", *host = "0.0.0.0";
	char *repo = "/var/lib/sks/keys.git/";
	char *group = "sks", *user = "sks";
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	state.pidfile = NULL;
	state.lmtpsock = NULL;

	int mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

	git_libgit2_init();

	handle_sigs();

	ARGBEGIN {
	case 'p':
		port = EARGF(usage());
		break;
	case 'h':
		host = EARGF(usage());
		break;
	case 'k':
		repo = EARGF(usage());
		break;
	case 'G':
		group = EARGF(usage());

		errno = 0;
		if (!(gr = getgrnam(group))) {
			if (errno) {
				die("getgrnam '%s':", group);
			} else {
				die("Entry not found.");
			}
		}
		break;
	case 'U':
		user = EARGF(usage());

		errno = 0;
		if (!(pw = getpwnam(user))) {
			if (errno) {
				die("getpwnam '%s':", user);
			} else {
				die("Entry not found.");
			}
		}
		break;
	case 'P':
		state.pidfile = EARGF(usage());
		break;
	case 'L':
		state.lmtpsock = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (!state.pidfile || !state.lmtpsock) {
		if (mkdir("/run/sks", mode) < 0 && errno != EEXIST)
			die("mkdir '/run/sks/':");

		state.pidfile = "/run/sks/sks.pid";
		state.lmtpsock = "/run/sks/sks.sock";
	}

	if (!gr)
		die("No group set");
	if (!pw)
		die("No user set");

	httpfd = get_in_sock(host, port);
	lmtpfd = get_unix_sock(state.lmtpsock, pw->pw_uid, gr->gr_gid);

	if (setgid(gr->gr_gid) || setuid(pw->pw_uid)) {
	    die("Dropping privileges:");
	}

	setpgid(0, 0);

	write_pidfile();

	if (git_repository_open_bare(&state.repo, repo) < 0) {
		const git_error *e = git_error_last();
		die("git_repository_open_bare: %d %s", e->klass, e->message);
	}

	for (;;) {
		struct sockaddr client;
		socklen_t client_len = sizeof(client);

		if ((cfd = accept(httpfd , &client, &client_len)) < 0)
			continue;

		pthread_t thread;
		pthread_create(&thread, NULL, handle_http, &cfd);
		pthread_detach(thread);
	}

	git_repository_free(state.repo);
	git_libgit2_shutdown();
	return EXIT_SUCCESS;
}

void* handle_http(void *arg) {
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
	static const  char *reply = "HTTP/1.1 500 Internal Server Error\r\n"
	                            "Content-Length: 0\r\n"
	                            "\r\n";

	send(clientfd, reply, strlen(reply), 0);
}

void not_found(int clientfd) {
	static const char *reply = "HTTP/1.1 404 Not Found\r\n"
	                           "Content-Length: 0\r\n"
				   "\r\n";

	send(clientfd, reply, strlen(reply), 0);
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

	if (strlen(hash) != 32) {
		logerr("Expected hash length to be 32, got %zu", strlen(hash));
		bad_request(clientfd);
		return;
	}

	if(!is_zbase32_chars(hash)) {
		logerr("Hash is not valid zbase32");
		bad_request(clientfd);
		return;
	}

	git_repository *repo = state.repo;
	git_oid oid;
	git_commit *commit;
	git_tree *tree = NULL;
	git_tree_entry *tree_entry = NULL;

	if (git_reference_name_to_id(&oid, repo, "HEAD") < 0) {
		logerr("Couldn't get HEAD reference:");
		internal_server_error(clientfd);
		return;
	}

	if (git_commit_lookup(&commit, repo, &oid) < 0) {
		logerr("Couldn't look up object id in git database:");
		internal_server_error(clientfd);
		return;
	}

	if (git_commit_tree(&tree, commit) < 0) {
		logerr("Couldn't get tree for commit:");
		internal_server_error(clientfd);
		return;
	}

	// Split into directories by starting hash letter
	char dirstr[2] = {hash[0], '\0'};

	if (git_tree_entry_bypath(&tree_entry, tree, dirstr) < 0) {
		logerr("Couldn't find '%s/' subdirectory:", dirstr);
		not_found(clientfd);
		return;
	}

	if (git_tree_entry_type(tree_entry) != GIT_OBJECT_TREE) {
		logerr("Expected a directory '%s/', not a file:", dirstr);
		internal_server_error(clientfd);
		return;
	}

	git_tree *dir = NULL;
	if (git_tree_lookup(&dir, repo, git_tree_entry_id(tree_entry)) < 0) {
		logerr("Couldn't look-up '%s/' tree:", dirstr);
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

		if (strncmp(hash, name, 32) == 0) {
			printf("Sending '%s'\n", name);

			git_blob *blob;
			if (git_blob_lookup(&blob, repo, oid) < 0) {
				const git_error *e = git_error_last();
				fprintf(stderr, "Couldn't read blob '%s' %d: %s\n", name, e->klass, e->message);
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

/*
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
*/
