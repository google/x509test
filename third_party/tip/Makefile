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
# source tree from upstream tip.
####################################


####################################
# OpenSSL
####################################
OPENSSL_REPO=git://git.openssl.org/openssl.git
OPENSSL_BRANCH=master
openssl:
	mkdir -p $@
openssl/config: | openssl
	git clone $(OPENSSL_REPO) openssl
	cd openssl && git checkout $(OPENSSL_BRANCH)
src-openssl: openssl/config
sync-openssl:
	cd openssl && git pull origin $(OPENSSL_BRANCH)

####################################
# BoringSSL
####################################
BORINGSSL_REPO=https://boringssl.googlesource.com/boringssl
BORINGSSL_BRANCH=master
boringssl:
	mkdir -p $@
boringssl/CMakeLists.txt: | boringssl
	git clone $(BORINGSSL_REPO) boringssl
	cd boringssl && git checkout $(BORINGSSL_BRANCH)
src-boringssl: boringssl/CMakeLists.txt
sync-boringssl:
	cd boringssl && git pull origin $(BORINGSSL_BRANCH)

####################################
# GnuTLS
####################################
GNUTLS_REPO=https://gitlab.com/gnutls/gnutls.git
GNUTLS_BRANCH=master
GNUTLS_PATCHES=$(wildcard $(CURDIR)/patches/gnutls/*.patch)
gnutls:
	mkdir -p $@
gnutls/GNUmakefile: | gnutls
	git clone $(GNUTLS_REPO) gnutls
	cd gnutls && git checkout $(GNUTLS_BRANCH)
	cd gnutls && if [ ! -z "$(GNUTLS_PATCHES)" ]; then git am $(GNUTLS_PATCHES); fi
gnutls/configure: | gnutls/GNUmakefile
	cd gnutls && make bootstrap
src-gnutls: gnutls/configure
sync-gnutls:
	cd gnutls && git pull origin $(GNUTLS_BRANCH)

####################################
# NSS
####################################
NSS_REPO=https://hg.mozilla.org/projects/nss
NSPR_REPO=https://hg.mozilla.org/projects/nspr
nss:
	mkdir -p $@
nss/nspr: | nss
	cd nss && hg clone $(NSPR_REPO)
nss/nss: | nss
	cd nss && hg clone $(NSS_REPO)
src-nss: | nss/nss nss/nspr

