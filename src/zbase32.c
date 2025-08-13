#include "zbase32.h"

static const char Alphabet[256] = {
    ['y']=1, ['b']=1, ['n']=1, ['d']=1, ['r']=1, ['f']=1,
    ['g']=1, ['8']=1, ['e']=1, ['j']=1, ['k']=1, ['m']=1,
    ['c']=1, ['p']=1, ['q']=1, ['x']=1, ['o']=1, ['t']=1,
    ['1']=1, ['u']=1, ['w']=1, ['i']=1, ['s']=1, ['z']=1,
    ['a']=1, ['3']=1, ['4']=1, ['5']=1, ['h']=1, ['7']=1,
    ['6']=1, ['9']=1,
};

int is_zbase32_chars(const char* src) {
	for (; *src; src++) {
		if (!Alphabet[(unsigned char)*src])
			return 0;
	}
	return 1;
}
