# See LICENSE file for copyright and license details
# SKS - simple key server
.POSIX:

include config.mk

COMPONENTS = queue sock uri util zbase32

all: sks

main.o: main.c arg.h queue.h sock.h uri.h util.h zbase32.h config.mk
queue.o: queue.c util.h queue.h config.mk
sock.o: sock.c config.h sock.h util.h config.mk
uri.o: uri.c config.h uri.h config.mk
zbase32.o: zbase32.c zbase32.h config.mk
util.o: util.c util.h config.mk


sks: config.h $(COMPONENTS:=.o) $(COMPONENTS:=.h) main.o config.mk
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(COMPONENTS:=.o) main.o $(LDFLAGS)

config.h:
	cp config.def.h $@

clean:
	rm -f sks main.o $(COMPONENTS:=.o)

dist:
	rm -rf "sks-$(VERSION)"
	mkdir -p "sks-$(VERSION)"
	cp -R LICENSE Makefile arg.h config.def.h config.mk sks.1 \
		$(COMPONENTS:=.c) $(COMPONENTS:=.h) main.c "sks-$(VERSION)"
	tar -cf - "sks-$(VERSION)" | gzip -c > "sks-$(VERSION).tar.gz"
	rm -rf "sks-$(VERSION)"

install: all
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp -f sks "$(DESTDIR)$(PREFIX)/bin"
	chmod 755 "$(DESTDIR)$(PREFIX)/bin/sks"
	mkdir -p "$(DESTDIR)$(MANPREFIX)/man1"
	cp sks.1 "$(DESTDIR)$(MANPREFIX)/man1/sks.1"
	chmod 644 "$(DESTDIR)$(MANPREFIX)/man1/sks.1"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/sks"
	rm -f "$(DESTDIR)$(MANPREFIX)/man1/sks.1"
