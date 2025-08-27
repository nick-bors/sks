static char *parse_token(char **, char);

char *
parse_token(char **s, char delim)
{
	char *start = *s;
	char *end = strchr(start, delim);

	if (!end)
		return NULL;
	
	*end = '\0';
	*s = ++end;

	return start;
}

int hex_to_int(char c) {
	if ('0' <= c && c <= '9') return c - '0';
	if ('a' <= c && c <= 'f') return c - 'a' + 10;
	if ('A' <= c && c <= 'F') return c - 'A' + 10;
	return -1;
}

typedef struct {
	int method;
	const char *resource;
	size_t resource_len;
	struct {
		const char *key;
		const char *value;
	} params[];
	size_t params_len;
} RequestLine;
