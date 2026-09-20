CFLAGS ?= -O2 -g -Wall -Wextra -Werror
PREFIX ?= /usr/local

all: fatrace tests/slow-exit.so tests/simple-touch tests/unit-tests

fatrace: fatrace.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o tests/*.o fatrace tests/slow-exit.so tests/simple-touch tests/unit-tests

distclean: clean

install: fatrace
	install -m 755 -D fatrace $(DESTDIR)$(PREFIX)/sbin/fatrace
	install -m 755 power-usage-report $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man8/
	install -m 644 *.8 $(DESTDIR)$(PREFIX)/share/man/man8/

tests/slow-exit.so: tests/slow-exit.c
	$(CC) -shared -fPIC -o $@ $< -ldl

tests/simple-touch: tests/simple-touch.c
	$(CC) $(CFLAGS) -o $@ $<

tests/unit-tests.o: fatrace.c

tests/unit-tests: tests/unit-tests.o
	$(CC) $(LDFLAGS) -o $@ $<

check: tests/unit-tests
	tests/unit-tests

lint:
	ruff check --extend-select E501 --line-length 118 power-usage-report
	ruff check --extend-select E501 --line-length 118 tests
	mypy power-usage-report
	mypy tests


.PHONY: all check clean distclean install lint
