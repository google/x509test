# Where to install build binaries/libraries etc.
INSTROOT=$(CURDIR)/instroot
instroot:
	mkdir -p $@
# Where to install configuration files etc.
CFGROOT=$(INSTROOT)/cfg
instroot/cfg: | instroot
	mkdir -p $@

downloads:
	mkdir -p $@
deps:
	mkdir -p $@

# The following targets often pick a single file to use as a bellwether for
# detecting that a rebuild is needed; proper dependency management is not
# included.

####################################
# OpenSSL
####################################
# Configure build
cfg-openssl: openssl/Makefile
openssl/Makefile: openssl/config
	cd openssl && ./config --prefix=$(INSTROOT) --openssldir=$(CFGROOT)/openssl
	cd openssl && $(MAKE) depend
bld-openssl: openssl/apps/openssl
openssl/apps/openssl: openssl/Makefile
	cd openssl && $(MAKE)
inst-openssl: instroot/bin/openssl
instroot/bin/openssl : openssl/apps/openssl | instroot/cfg
	cd openssl && $(MAKE) install_sw

####################################
# BoringSSL
####################################
# Configure build
cfg-boringssl: boringssl/build/Makefile
boringssl/build:
	mkdir -p $@
boringssl/build/Makefile: boringssl/CMakeLists.txt | boringssl/build
	cd boringssl/build && cmake ..
bld-boringssl: boringssl/build/tool/bssl
boringssl/build/tool/bssl: boringssl/build/Makefile
	cd boringssl/build && $(MAKE)
inst-boringssl: instroot/bin/bssl
instroot/bin/bssl : boringssl/build/tool/bssl | instroot instroot/cfg
	cp -p $< $@

####################################
# GnuTLS
####################################
# Configure build
cfg-gnutls: gnutls/Makefile
gnutls/build:
	mkdir -p $@
gnutls/Makefile: gnutls/configure instroot/lib/libnettle.a instroot/lib/libgmp.a
	cd gnutls/ && PKG_CONFIG_PATH=$(INSTROOT)/lib/pkgconfig ./configure --prefix=$(INSTROOT) --with-included-libtasn1 --without-p11-kit --without-tpm
bld-gnutls: gnutls/src/certtool
gnutls/src/certtool: gnutls/Makefile
	cd gnutls && $(MAKE)
inst-gnutls: instroot/bin/certtool
instroot/bin/certtool: gnutls/src/certtool
	cd gnutls && $(MAKE) install-exec

####################################
# GnuTLS dependency: gmp
####################################
GMP_VERSION=gmp-6.1.0
GMP_TARBALL=$(GMP_VERSION).tar.bz2
GMP_URL=https://gmplib.org/download/gmp/$(GMP_TARBALL)
downloads/$(GMP_TARBALL): | downloads
	cd downloads && wget $(GMP_URL)
deps/$(GMP_VERSION): downloads/$(GMP_TARBALL) | deps
	cd deps && tar xf ../$<
deps/$(GMP_VERSION)/Makefile: | deps/$(GMP_VERSION)
	cd deps/$(GMP_VERSION) && ./configure --prefix=$(INSTROOT)
deps/$(GMP_VERSION)/libgmp.la: deps/$(GMP_VERSION)/Makefile
	cd deps/$(GMP_VERSION) && $(MAKE)
instroot/lib/libgmp.a: deps/$(GMP_VERSION)/libgmp.la
	cd deps/$(GMP_VERSION) && $(MAKE) install

####################################
# GnuTLS dependency: nettle
####################################
NETTLE_VERSION=nettle-3.2
NETTLE_TARBALL=$(NETTLE_VERSION).tar.gz
NETTLE_URL=https://ftp.gnu.org/gnu/nettle/$(NETTLE_TARBALL)
downloads/$(NETTLE_TARBALL): | downloads
	cd downloads && wget $(NETTLE_URL)
deps/$(NETTLE_VERSION): downloads/$(NETTLE_TARBALL) | deps
	cd deps && tar xf ../$<
deps/$(NETTLE_VERSION)/Makefile: | deps/$(NETTLE_VERSION)
	cd deps/$(NETTLE_VERSION) && ./configure --prefix=$(INSTROOT)
deps/$(NETTLE_VERSION)/libnettle.a: deps/$(NETTLE_VERSION)/Makefile
	cd deps/$(NETTLE_VERSION) && $(MAKE)
instroot/lib/libnettle.a: deps/$(NETTLE_VERSION)/libnettle.a
	cd deps/$(NETTLE_VERSION) && $(MAKE) install


####################################
# NSS
####################################
NSS_VARS=BUILD_OPT=1 USE_64=1
# Deduce the build subdirectory
OS_ARCH := $(subst /,_,$(shell uname -s))
OS_RELEASE := $(shell uname -r)
OS_RELEASE := $(shell echo $(OS_RELEASE) | sed 's/-.*//')
ifeq ($(OS_ARCH),Linux)
    OS_RELEASE := $(subst ., ,$(OS_RELEASE))
    ifneq ($(words $(OS_RELEASE)),1)
	OS_RELEASE := $(word 1,$(OS_RELEASE)).$(word 2,$(OS_RELEASE))
    endif
endif
NSS_BLD_SUBDIR=$(OS_ARCH)$(OS_RELEASE)_x86_64_cc_glibc_PTH_64_OPT.OBJ
bld-nss: nss/dist/$(NSS_BLD_SUBDIR)/bin/certutil
nss/dist/$(NSS_BLD_SUBDIR)/bin/certutil : | nss/nss nss/nspr
	cd nss/nss && $(NSS_VARS) $(MAKE) nss_build_all
inst-nss: instroot/bin/certutil
NSS_LIBS=libsmime3.so libnss3.so libnssutil3.so libplc4.so libplds4.so libnspr4.so
NSS_BLD_LIBS=$(addprefix nss/dist/$(NSS_BLD_SUBDIR)/lib/,$(NSS_LIBS))
NSS_INST_LIBS=$(addprefix instroot/lib/,$(NSS_LIBS))
instroot/bin/certutil: nss/dist/$(NSS_BLD_SUBDIR)/bin/certutil $(NSS_INST_LIBS)
	cp $< $@
instroot/lib/%.so: nss/dist/$(NSS_BLD_SUBDIR)/lib/%.so
	cp $< $@
# Note that LD_LIBRARY_PATH=instroot/lib is needed to use the build binaries.
