#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "util.h"
#include "config.h"

int
get_in_sock(const char *host, const char* port)
{
	struct addrinfo *ai, *cur;
	int e, sfd = 0;

	struct addrinfo hints = {
	    .ai_flags    = AI_NUMERICSERV,
	    .ai_family   = AF_UNSPEC,
	    .ai_socktype = SOCK_STREAM,
	};

	if ((e = getaddrinfo(host, port, &hints, &ai)) < 0)
		die("getaddrinfo: %s", gai_strerror(e));

	/* For each socket in the linked list, try binding until one socket is
	   found matching the hints: host, port and, TCP. */
	for (cur = ai; cur; cur = cur->ai_next) {
		if ((sfd = socket(cur->ai_family, cur->ai_socktype,
		                  cur->ai_protocol)) < 0) {
			continue;
		}
		
		/* Set REUSEADDR=1 to immediately re-start without TIME_WAIT */
		int reuse = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
		               sizeof(reuse)) < 0) {
			die("setsockopt:");
		}

		if (bind(sfd, cur->ai_addr, cur->ai_addrlen) < 0) {
			/* bind failed, close it and try another socket */
			if (close(sfd) < 0) {
				die("close:");
			}
			continue;
		}

		break;
	}
	freeaddrinfo(ai);

	if (!cur) {
		if (errno == EACCES) {
			die("Insufficient permissions to bind to a privileged "
			    "port. Re-run as root, chose a higher port number "
			    ">= 1024, or have CAP_NET_BIND_SERVICE set.");
		} else {
			die("bind:");
		}
	}

	if (listen(sfd, SOCKET_MAX_CONNS) < 0) {
		die("listen:");
	}
	
	return sfd;
}

int
get_unix_sock(const char *name, uid_t uid, gid_t gid)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};

	int sfd = 0;
	// File perms: RW-RW-RW-
	int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	size_t name_len;
	
	if ((name_len = strlen(name)) > sizeof(addr.sun_path) - 1)
		die("UNIX domain socket path truncated");

	memcpy(addr.sun_path, name, name_len + 1);

	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		die("socket:");
	}

	if (bind(sfd, (const struct sockaddr*)&addr, sizeof(addr)) < 0
	   && close(sfd) < 0)
		die("close:");

	if (listen(sfd, SOCKET_MAX_CONNS) < 0) {
		if (unlink(name) < 0)
			die("unlink %s:", name);
		die("listen:");
	}

	if (chmod(name, mode) < 0) {
		if (unlink(name) < 0)
			die("unlink %s:", name);
		die("chmod '%s':", name);
	}

	if (chown(name, uid, gid) < 0) {
		if (unlink(name) < 0)
			die("unlink %s:", name);
		die("chown '%s':", name);
	}

	return sfd;
}
