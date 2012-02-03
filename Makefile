CFLAGS ?= -O2 -g -Wall -Werror
PREFIX ?= /usr/local

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o fatrace

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/bin/fatrace

.PHONY: clean distclean install
