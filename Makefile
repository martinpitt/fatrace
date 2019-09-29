VERSION=$(shell head -n1 NEWS | cut -f1 -d' ')

CFLAGS ?= -O2 -g -Wall -Wextra -Werror
CFLAGS += -D_GNU_SOURCE
PREFIX ?= /usr/local

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o fatrace

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/sbin/fatrace
	install -m 755 power-usage-report $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 *.1 $(DESTDIR)$(PREFIX)/share/man/man1/

dist: distclean
	files=`ls *`; \
	mkdir fatrace-$(VERSION); \
	cp $$files fatrace-$(VERSION); \
	tar c fatrace-$(VERSION) | bzip2 -9 > fatrace-$(VERSION).tar.bz2; \
	rm -r fatrace-$(VERSION);

.PHONY: clean distclean install
