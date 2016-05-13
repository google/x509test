# Build all the TLS projects!
all: inst
include ../common/Makefile

# Set up source trees
src: src-openssl src-boringssl src-gnutls src-nss # src-libressl src-nss src-gnutls src-wolfssl src-mbedtls src-matrixssl src-nqsbtls
# Build
bld: bld-openssl bld-boringssl bld-gnutls bls-nss
# Install to local dir
inst: inst-openssl inst-boringssl inst-gnutls inst-nss


####################################
# Per-codebase targets to set up
# source tree from stable upstream versions.
####################################


####################################
# OpenSSL
####################################
OPENSSL_VERSION=openssl-1.0.2h
OPENSSL_TARBALL=$(OPENSSL_VERSION).tar.gz
OPENSSL_URL=https://www.openssl.org/source/$(OPENSSL_TARBALL)
downloads/$(OPENSSL_TARBALL): | downloads
	cd downloads && wget $(OPENSSL_URL)
$(OPENSSL_VERSION): downloads/$(OPENSSL_TARBALL)
	tar xf $<
	rm $(OPENSSL_VERSION)/Makefile  # Force re-config
openssl: | $(OPENSSL_VERSION)
	ln -s $(OPENSSL_VERSION) $@
openssl/config: | openssl
src-openssl: openssl/config

####################################
# BoringSSL
####################################
BORINGSSL_REPO=https://boringssl.googlesource.com/boringssl
BORINGSSL_BRANCH=chromium-stable
boringssl:
	mkdir -p $@
boringssl/CMakeLists.txt: | boringssl
	git clone $(BORINGSSL_REPO) boringssl
	cd boringssl && git checkout $(BORINGSSL_BRANCH)
src-boringssl: boringssl/CMakeLists.txt

####################################
# GnuTLS
####################################
GNUTLS_VERSION=gnutls-3.4.11
GNUTLS_TARBALL=$(GNUTLS_VERSION).tar.xz
GNUTLS_URL= ftp://ftp.gnutls.org/gcrypt/gnutls/v3.4/$(GNUTLS_TARBALL)
downloads/$(GNUTLS_TARBALL): | downloads
	cd downloads && wget $(GNUTLS_URL)
$(GNUTLS_VERSION)/configure: downloads/$(GNUTLS_TARBALL)
	tar xf $<
	touch $@
gnutls: $(GNUTLS_VERSION)/configure
	ln -s $(GNUTLS_VERSION) $@
gnutls/configure: | gnutls
src-gnutls: gnutls/configure

####################################
# NSS
####################################
NSS_VERSION=nss-3.23
NSS_TARBALL=nss-3.23-with-nspr-4.12.tar.gz
NSS_URL=https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_23_RTM/src/$(NSS_TARBALL)
downloads/$(NSS_TARBALL): | downloads
	cd downloads && wget $(NSS_URL)
$(NSS_VERSION): downloads/$(NSS_TARBALL)
	tar xf $<
nss: $(NSS_VERSION)
	ln -s $(NSS_VERSION) nss
nss/nss: | nss
src-nss: nss/nss
