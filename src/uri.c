#include <stdlib.h>
#include <string.h>

#include "uri.h"

int hex_to_int(char);
int percent_decode(char *);

int parse_uri(Uri *out, char *uri) {
	if(!out)
		return -1;

	memset(out, 0, sizeof(Uri));

	char *cur = uri;
	out->resource = cur;
	
	cur = strchr(cur, '?');
	if (!cur)
		return 0;
	out->params_count++;
	*cur++ = '\0';

	// Pre-compute buffer length
	for (char *p = cur; *p; p++) {
		if (*p == '&')
			out->params_count++;
	}
	
	out->params = malloc(out->params_count * sizeof(QueryPair));

	for (size_t i = 0; i < out->params_count; i++) {
		out->params[i].key = cur;
		cur = strchr(cur, '=');
		*cur++ = '\0';

		if(percent_decode((char *)out->params[i].key) < 0)
			return -1;

		out->params[i].value = cur;
		cur = strchr(cur, '&');
		if (cur)
			*cur++ = '\0';

		if(percent_decode((char *)out->params[i].value) < 0)
			return -1;
	}

	return 0;
}

int hex_to_int(char c) {
	if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

int percent_decode(char* src) {
	char *dst = src;

	while (*src) {
		if (*src == '%') {
			int hi = hex_to_int(src[1]);
			int lo = hex_to_int(src[2]);

			if (hi < 0 || lo < 0)
				return -1;
			
			*src = (hi << 4) | lo;
			*dst++ = *src;
			src += 3;
		} else {
			*dst++ = *src++;
		}
	}

	*dst = '\0';

	return 0;
}
