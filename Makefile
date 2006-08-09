CPPFLAGS =
CFLAGS = -g3 -Wall -O0 -Werror-implicit-function-declaration -MD
LDFLAGS = -lpam
LIB = /lib

CPPFLAGS += -DHAVE_GCCVISIBILITY
CFLAGS += -fvisibility=hidden

all: pam_testprompt.so

pam_testprompt.o: pam_testprompt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $<

pam_testprompt.so: pam_testprompt.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ -fPIC -shared -Wl,-z,defs -lpam $?

install:
	install -d -m 755 $(DESTDIR)/etc/security
	install -d -m 755 $(DESTDIR)/etc/pam.d
	install -d -m 755 $(DESTDIR)$(LIB)/security
	install -m 644 etc/pam.d/* $(DESTDIR)/etc/pam.d
	install -m 644 etc/security/*.conf $(DESTDIR)/etc/security
	install -m 755 pam_testprompt.so $(DESTDIR)$(LIB)/security

clean:
	rm -f -- *.o *.d *.so* tags

-include *.d

.PHONY: clean
