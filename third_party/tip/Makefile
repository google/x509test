# Build all the TLS projects!

all: inst


# Set up source trees
src: src-openssl src-boringssl src-gnutls # src-libressl src-nss src-gnutls src-wolfssl src-mbedtls src-matrixssl src-nqsbtls
# Build
bld: bld-openssl bld-boringssl bld-gnutls
# Install to local dir
inst: inst-openssl inst-boringssl inst-gnutls

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
OPENSSL_REPO=git://git.openssl.org/openssl.git
OPENSSL_BRANCH=master
# Retrieve code
openssl:
	mkdir -p $@
openssl/config: | openssl
	git clone $(OPENSSL_REPO) openssl
	cd openssl && git checkout $(OPENSSL_BRANCH)
src-openssl: openssl/config
sync-openssl:
	cd openssl && git pull origin $(OPENSSL_BRANCH)
# Configure build
cfg-openssl: openssl/Makefile
openssl/Makefile: openssl/config
	cd openssl && ./config --prefix=$(INSTROOT) --openssldir=$(CFGROOT)/openssl
bld-openssl: openssl/apps/openssl
openssl/apps/openssl: openssl/Makefile
	cd openssl && $(MAKE)
inst-openssl: instroot/bin/openssl
instroot/bin/openssl : openssl/apps/openssl | instroot/cfg
	cd openssl && $(MAKE) install_sw

####################################
# BoringSSL
####################################
BORINGSSL_REPO=https://boringssl.googlesource.com/boringssl
BORINGSSL_BRANCH=master
# Retrieve code
boringssl:
	mkdir -p $@
boringssl/CMakeLists.txt: | boringssl
	git clone $(BORINGSSL_REPO) boringssl
	cd boringssl && git checkout $(BORINGSSL_BRANCH)
src-boringssl: boringssl/CMakeLists.txt
sync-boringssl:
	cd boringssl && git pull origin $(BORINGSSL_BRANCH)
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
GNUTLS_REPO=https://gitlab.com/gnutls/gnutls.git
GNUTLS_BRANCH=master
GNUTLS_PATCHES=$(wildcard $(CURDIR)/patches/gnutls/*.patch)
# Retrieve code
gnutls:
	mkdir -p $@
gnutls/configure: | gnutls
	git clone $(GNUTLS_REPO) gnutls
	cd gnutls && git checkout $(GNUTLS_BRANCH)
	cd gnutls && if [ ! -z "$(GNUTLS_PATCHES)" ]; then git am $(GNUTLS_PATCHES); fi
	cd gnutls && make bootstrap
src-gnutls: gnutls/configure
sync-gnutls:
	cd gnutls && git pull origin $(GNUTLS_BRANCH)
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



