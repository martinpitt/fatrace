VERSION=$(shell head -n1 NEWS | cut -f1 -d' ')

CFLAGS ?= -O2 -g -Wall -Wextra -Werror
PREFIX ?= /usr/local

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o fatrace

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/sbin/fatrace
	install -m 755 power-usage-report $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 *.8 $(DESTDIR)$(PREFIX)/share/man/man8/

dist:
	git ls-tree -r --full-name --name-only HEAD | tar cJvf fatrace-$(VERSION).tar.xz --transform="s,^,fatrace-$(VERSION)/," --exclude=.gitignore --files-from=-

.PHONY: clean distclean dist install
