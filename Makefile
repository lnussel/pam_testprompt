CPPFLAGS =
CFLAGS = -g3 -Wall -O0 -Werror-implicit-function-declaration -MD
LDLIBS = -lpam
LIB = /lib

CPPFLAGS += -DHAVE_GCCVISIBILITY
CFLAGS += -fvisibility=hidden

VERSION=0.0
ifeq ($(wildcard .git),.git)
  _VERSION=$(VERSION)+$(shell LANG=C git log -n1 --date=short --pretty=format:"git%cd.%h"|sed 's@-@@g')
else
  _VERSION=$(VERSION)
endif

all: pam_testprompt.so

pam_testprompt.o: pam_testprompt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $<

pam_testprompt.so: pam_testprompt.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ -fPIC -shared -Wl,-z,defs $? $(LDLIBS)

install: all
	install -d -m 755 $(DESTDIR)/etc/security
	install -d -m 755 $(DESTDIR)/etc/pam.d
	install -d -m 755 $(DESTDIR)$(LIB)/security
	install -m 644 etc/pam.d/* $(DESTDIR)/etc/pam.d
	install -m 644 etc/security/*.conf $(DESTDIR)/etc/security
	install -m 755 pam_testprompt.so $(DESTDIR)$(LIB)/security

clean:
	rm -f -- *.o *.d *.so* tags

-include *.d

dist:
	git archive --prefix="pam_testprompt-$(_VERSION)"/ HEAD | xz > pam_testprompt-$(_VERSION).tar.xz

.PHONY: clean dist
