CFLAGS ?= -O2 -g -Wall -Wextra -Werror
PREFIX ?= /usr/local

all: fatrace tests/slow-exit.so

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o fatrace tests/slow-exit.so

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/sbin/fatrace
	install -m 755 power-usage-report $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 *.8 $(DESTDIR)$(PREFIX)/share/man/man8/

tests/slow-exit.so: tests/slow-exit.c
	$(CC) -shared -fPIC -o $@ $< -ldl


.PHONY: all clean distclean install
