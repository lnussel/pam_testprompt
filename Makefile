CPPFLAGS =
CFLAGS = -g3 -Wall -O0 -Werror-implicit-function-declaration -MD
LDFLAGS = -lpam
LIB = /lib

CPPFLAGS += -DHAVE_GCCVISIBILITY
CFLAGS += -fvisibility=hidden

SONAME = libpamwrapper.so.0

all: pamwrapper libpamwrapper.so pwsu pam_testprompt.so

pamwrapper: pamwrapper.o cfgfile.o logging.o

libpamwrapper.o: libpamwrapper.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $<

$(SONAME): libpamwrapper.map
$(SONAME): libpamwrapper.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ -shared -fPIC -Wl,-z,defs -Wl,--soname,$(SONAME) -Wl,--version-script=libpamwrapper.map $<

libpamwrapper.so: $(SONAME)
	test -L $@ || ln -s $(SONAME) $@

pam_testprompt.o: pam_testprompt.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $<

pam_testprompt.so: pam_testprompt.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ -fPIC -shared -Wl,-z,defs -lpam $?

pwsu: libpamwrapper.so
pwsu: pwsu.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ $< -L. -lpamwrapper -Wl,-rpath,\$$ORIGIN

suid: pamwrapper
	sudo chown root pamwrapper
	sudo chmod 4755 pamwrapper

install:
	install -d -m 755 $(DESTDIR)/bin $(DESTDIR)/sbin $(DESTDIR)$(LIB) $(DESTDIR)/usr/include
	install -d -m 755 $(DESTDIR)/etc/security/console.apps
	install -d -m 755 $(DESTDIR)/etc/pam.d
	install -d -m 755 $(DESTDIR)$(LIB)/security
	install -m 4755 pamwrapper $(DESTDIR)/sbin
	install -m 755 pwsu $(DESTDIR)/bin
	install -m 755 $(SONAME) $(DESTDIR)$(LIB)
	install -m 755 libpamwrapper.so $(DESTDIR)$(LIB)
	install -m 644 etc/security/console.apps/* $(DESTDIR)/etc/security/console.apps
	install -m 644 etc/pam.d/* $(DESTDIR)/etc/pam.d
	install -m 644 etc/security/*.conf $(DESTDIR)/etc/security
	install -m 644 libpamwrapper.h $(DESTDIR)/usr/include
	install -m 755 pam_testprompt.so $(DESTDIR)$(LIB)/security

clean:
	rm -f -- *.o pamwrapper *.d *.so* pwsu tags

-include *.d

.PHONY: clean suid
