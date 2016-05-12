# Build all the TLS projects!

all:

# Set up source trees
src: src-openssl src-boringssl # src-libressl src-nss src-gnutls src-wolfssl src-mbedtls src-matrixssl src-nqsbtls

# Where to install build binaries/libraries etc.
INSTROOT=$(CURDIR)/instroot
instroot:
	mkdir -p $@
# Where to install configuration files etc.
CFGROOT=$(INSTROOT)/cfg
instroot/cfg: | instroot
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
install-openssl: instroot/bin/openssl
instroot/bin/openssl : openssl/apps/openssl | instroot instroot/cfg
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
bld-boringssl: boringssl/apps/boringssl
boringssl/build/tool/bssl: boringssl/build/Makefile
	cd boringssl/build && $(MAKE)
install-boringssl: instroot/bin/bssl
instroot/bin/bssl : boringssl/build/tool/bssl | instroot instroot/cfg
	cp -p $< $@
