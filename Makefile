CC = gcc
CFLAGS = -O2 -Wall -Werror

SECCOMP_SOURCES = seccomp.c seccomp.h main.c

CHECK_SOURCES = unit-tests/unit-tests.c seccomp.c
CHECK_INCLUDES = $(shell pkg-config --cflags glib-2.0) -I.
CHECK_LIBS = $(shell pkg-config --libs glib-2.0)

all: seccomp-load unit-tests/unit-tests

seccomp-load: $(SECCOMP_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^

unit-tests/unit-tests: $(CHECK_SOURCES)
	$(CC) $(CFLAGS) $(CHECK_INCLUDES) -o unit-tests/unit-tests $^  $(CHECK_LIBS)

check: unit-tests/unit-tests
	@./unit-tests/unit-tests

.PHONY: clean check

clean:
	rm -f seccomp-load unit-tests/unit-tests
