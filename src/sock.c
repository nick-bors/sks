#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#include "util.h"

#define SOCKET_MAX_CONNS 10

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
