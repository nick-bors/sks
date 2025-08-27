CC=cc
CFLAGS=-Wall -Wextra -pedantic -O3 -g3 -fsanitize=address -std=c99 \
       -D_XOPEN_SOURCE=700
LDFLAGS=-lgit2 -fsanitize=address

SRC=$(wildcard src/*.c)
INCLUDES=-I.
OBJ=$(SRC:.c=.o)

CONFIG_FILES=$(wildcard *.glsl) $(wildcard *.conf)

NAME=sks

PREFIX ?= /usr
MANDIR ?= $(PREFIX)/man
DOCPREFIX ?= ${PREFIX}/share/doc/${NAME}

DOC = \
	  LICENSE \
	  README.md
MAN1 = \
	   sks.1

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $(NAME) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f ${NAME} ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/${NAME}
	# installing example files.
	mkdir -p ${DESTDIR}${DOCPREFIX}
	cp -f \
		vertex.glsl\
		fragment.glsl\
		LICENSE\
		zooc.conf\
		README.sh\
		${DESTDIR}${DOCPREFIX}
	# installing manual pages.
	mkdir -p ${DESTDIR}${MANPREFIX}/man1
	cp -f ${MAN1} ${DESTDIR}${MANPREFIX}/man1
	for m in ${MAN1}; do chmod 644 ${DESTDIR}${MANPREFIX}/man1/$$m; done

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/${NAME}
	# removing example files.
	rm -f \
		${DESTDIR}${DOCPREFIX}/vertex.glsl\
		${DESTDIR}${DOCPREFIX}/fragment.glsl\
		${DESTDIR}${DOCPREFIX}/LICENSE\
		${DESTDIR}${DOCPREFIX}/zooc.conf\
		${DESTDIR}${DOCPREFIX}/README.sh\
		-rmdir ${DESTDIR}${DOCPREFIX}
	# removing manual pages.
	for m in ${MAN1}; do rm -f ${DESTDIR}${MANPREFIX}/man1/$$m; done

clean:
	rm -f ${NAME} ${OBJ}

.PHONY: all clean install uninstall
