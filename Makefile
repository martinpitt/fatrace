VERSION=0.1

CFLAGS ?= -O2 -g -Wall -Werror
PREFIX ?= /usr/local

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o fatrace

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/bin/fatrace

dist: distclean
	files=`ls *`; \
	mkdir fatrace-$(VERSION); \
	cp $$files fatrace-$(VERSION); \
	tar c fatrace-$(VERSION) | bzip2 -9 > fatrace-$(VERSION).tar.bz2; \
	rm -r fatrace-$(VERSION);

.PHONY: clean distclean install
