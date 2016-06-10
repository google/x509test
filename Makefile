# X.509 Certificate Testing driver

# Prerequisite: der2ascii and ascii2der from:
#   `go get github.com/google/der-ascii/cmd/...`

# Examine the TLS environment variable to determine which tools to test
TLS ?= installed
ifeq ($(TLS),installed)
  # Use installed versions, assumed to be in path
  PREREQS = libnss3-tools gnutls-bin openssl
  DEPS = pkg-install
  OPENSSL = openssl
  BORINGSSL = bssl
  CERTUTIL = certutil
  CERTTOOL = certtool
else ifeq ($(TLS),stable)
  # Use local versions built from stable.  Run `make tls-stable-bld` to populate.
  DEPS = tls-stable-bld
  OPENSSL = third_party/stable/instroot/bin/openssl
  BORINGSSL = third_party/stable/instroot/bin/bssl
  CERTUTIL = third_party/stable/instroot/bin/certutil
  CERTTOOL = third_party/stable/instroot/bin/certtool
else ifeq ($(TLS),tip)
  # Use local versions built from stable.  Run `make tls-tip-bld` to populate.
  DEPS = tls-tip-bld
  OPENSSL = third_party/tip/instroot/bin/openssl
  BORINGSSL = third_party/tip/instroot/bin/bssl
  CERTUTIL = third_party/tip/instroot/bin/certutil
  CERTTOOL = third_party/tip/instroot/bin/certtool
else
  $(error Unknown TLS tool selection $(TLS))
endif
# Tip-code only tools
X509LINT = third_party/tip/instroot/bin/x509lint

TBS_FILES = $(subst tbs/,,$(wildcard tbs/*.tbs))

RESULTS_OPENSSL_OK = $(addprefix results/openssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
# @@@ RESULTS_BORINGSSL_OK = $(addprefix results/boringssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_GNUTLS_OK = $(addprefix results/gnutls/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_NSS_OK = $(addprefix results/nss/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_X509LINT_OK = $(addprefix results/x509lint/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))

RESULTS_OPENSSL_XF = $(addprefix results/openssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
# @@@ RESULTS_BORINGSSL_XF = $(addprefix results/boringssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_GNUTLS_XF = $(addprefix results/gnutls/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_NSS_XF = $(addprefix results/nss/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_X509LINT_XF = $(addprefix results/x509lint/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))

RESULTS_OPENSSL = $(RESULTS_OPENSSL_OK) $(RESULTS_OPENSSL_XF)
RESULTS_BORINGSSL = $(RESULTS_BORINGSSL_OK) $(RESULTS_BORINGSSL_XF)
RESULTS_GNUTLS = $(RESULTS_GNUTLS_OK) $(RESULTS_GNUTLS_XF)
RESULTS_NSS = $(RESULTS_NSS_OK) $(RESULTS_NSS_XF)
RESULTS_X509LINT = $(RESULTS_X509LINT_OK) $(RESULTS_X509LINT_XF)

RESULTS_OK = $(RESULTS_OPENSSL_OK) $(RESULTS_BORINGSSL_OK) $(RESULTS_GNUTLS_OK) $(RESULTS_NSS_OK) $(RESULTS_X509LINT_OK)
RESULTS_XF = $(RESULTS_OPENSSL_XF) $(RESULTS_BORINGSSL_XF) $(RESULTS_GNUTLS_XF) $(RESULTS_NSS_XF) $(RESULTS_X509LINT_XF)
RESULTS = $(RESULTS_OPENSSL) $(RESULTS_BORINGSSL) $(RESULTS_GNUTLS) $(RESULTS_NSS) $(RESULTS_X509LINT)

all: check

check: $(RESULTS) check-ok check-xf
check-ok: $(RESULTS_OK)
	@scripts/display Valid $(TLS)
check-xf: $(RESULTS_XF)
	@scripts/display Invalid $(TLS)
check-openssl: check-openssl-ok check-openssl-xf
check-openssl-ok: $(RESULTS_OPENSSL_OK)
	@scripts/display Valid $(TLS) OpenSSL
check-openssl-xf: $(RESULTS_OPENSSL_XF)
	@scripts/display Invalid $(TLS) OpenSSL
check-boringssl: check-boringssl-ok check-boringssl-xf
check-boringssl-ok: $(RESULTS_BORINGSSL_OK)
	@scripts/display Valid $(TLS) BoringSSL
check-boringssl-xf: $(RESULTS_BORINGSSL_XF)
	@scripts/display Invalid $(TLS) BoringSSL
check-gnutls: check-gnutls-ok check-gnutls-xf
check-gnutls-ok: $(RESULTS_GNUTLS_OK)
	@scripts/display Valid $(TLS) GnuTLS
check-gnutls-xf: $(RESULTS_GNUTLS_XF)
	@scripts/display Invalid $(TLS) GnuTLS
check-nss: check-nss-ok check-nss-xf
check-nss-ok: $(RESULTS_NSS_OK)
	@scripts/display Valid $(TLS) NSS
check-nss-xf: $(RESULTS_NSS_XF)
	@scripts/display Invalid $(TLS) NSS
check-x509lint: check-x509lint-ok check-x509lint-xf
check-x509lint-ok: $(RESULTS_X509LINT_OK)
	@scripts/display Valid tip x509lint
check-x509lint-xf: $(RESULTS_X509LINT_XF)
	@scripts/display Invalid tip x509lint

results-openssl: $(RESULTS_OPENSSL)
results-boringssl: $(RESULTS_BORINGSSL)
results-gnutls: $(RESULTS_GNUTLS)
results-nss: $(RESULTS_NSS)
results-x509lint: $(RESULTS_X509LINT)

# deps target prepares TLS tools; it depends on the TLS env var.
deps: $(DEPS)
pkg-install:
	sudo apt-get install $(PREREQS)
show-tls:
	@echo Using: $(OPENSSL) $(BORINGSSL) $(CERTUTIL) $(CERTTOOL) $(X509LINT)

###########################################
# TLS tool targets.
# Manual targets to build local copies.
###########################################
tls-tip-src:
	cd third_party/tip && $(MAKE) src
tls-tip-bld: tls-tip-src
	cd third_party/tip && $(MAKE)
tls-tip-inst: tls-tip-bld
	cd third_party/tip && $(MAKE) inst
tls-stable-src:
	cd third_party/stable && $(MAKE) src
tls-stable-bld: tls-stable-src
	cd third_party/stable && $(MAKE)
tls-stable-inst: tls-stable-bld
	cd third_party/stable && $(MAKE) inst


###########################################
# Run certs through TLS tools
###########################################
results:
	mkdir -p $@
results/openssl/$(TLS):
	mkdir -p $@
results/boringssl/$(TLS):
	mkdir -p $@
results/gnutls/$(TLS):
	mkdir -p $@
results/nss/$(TLS):
	mkdir -p $@
results/x509lint/$(TLS):
	mkdir -p $@
results/openssl/$(TLS)/%.out: certs/%.pem ca/fake-ca.cert | results/openssl/$(TLS)
	scripts/check-openssl $(OPENSSL) verify -x509_strict -CAfile ca/fake-ca.cert $< > $@ 2>&1
results/boringssl/$(TLS)/%.out: certs/%.pem ca/fake-ca.cert | results/boringssl/$(TLS)
	scripts/check-boringssl $(BORINGSSL) verify -CAfile ca/fake-ca.cert $< > $@ 2>&1
results/gnutls/$(TLS)/%.out: certs/%.chain.pem ca/fake-ca.cert | results/gnutls/$(TLS)
	scripts/check-certtool $(CERTTOOL) --verify-chain --load-ca-certificate ca/fake-ca.cert --infile $< >$@ 2>&1
results/nss/$(TLS)/%.out: certs/%.pem | results/nss/$(TLS) nss-db/cert8.db
	scripts/check-certutil $(CERTUTIL) $< > $@ 2>&1
results/x509lint/$(TLS)/%.out: certs/%.pem | results/x509lint/$(TLS)
	scripts/check-x509lint $(X509LINT) -c $< > $@ 2>&1

show-openssl-%: certs/%.pem
	$(OPENSSL) x509 -inform pem -in $< -text -noout
show-boringssl-%: certs/%.pem
	$(BORINGSSL) x509 -inform pem -in $< -text -noout
show-gnutls-%: certs/%.pem
	$(CERTTOOL) --certificate-info --infile $<
show-nss-%: certs/%.pem nss-db/cert8.db
	$(CERTUTIL) -A -d nss-db -n "Cert from $<" -t ,, -i $<
	$(CERTUTIL) -L -d nss-db -n "Cert from $<"
	$(CERTUTIL) -D -d nss-db -n "Cert from $<"


###########################################
# Fake CA set-up; uses OpenSSL as the most
# familiar tool.
###########################################
# Generate a keypair.  Note that these are *not* secret and *not* password-protected.
ca:
	mkdir -p $@
ca/fake-ca.private.pem: | ca
	$(OPENSSL) genpkey -algorithm RSA -out $@ -pkeyopt rsa_keygen_bits:2048
ca/%.public.pem: ca/%.private.pem
	$(OPENSSL) rsa -pubout -in $< -out $@
# Generate a self-signed certificate.
ca/fake-ca.cert: ca/fake-ca.private.pem cfg/fake-ca.cnf
	$(OPENSSL) req -new -x509 -config cfg/fake-ca.cnf -days 365 -extensions v3_ca -inform pem -key $< -out $@
ca/fake-ca.der: ca/fake-ca.cert
	$(OPENSSL) x509 -in $< -outform der -out $@
ca/fake-ca.ascii: ca/fake-ca.der
	der2ascii -i $< -o $@
# Show fake CA information.
show-ca-privkey: ca/fake-ca.private.pem
	$(OPENSSL) rsa -in $< -text -noout
show-ca-pubkey: ca/fake-ca.public.pem
	$(OPENSSL) rsa -pubin -in $< -text -noout
show-ca-cert: ca/fake-ca.cert
	$(OPENSSL) x509 -inform pem -in $< -text -noout

###########################################
# NSS database setup
###########################################
nss-db:
	mkdir -p $@
nss-db/cert8.db : ca/fake-ca.cert | nss-db
	$(CERTUTIL) -A -d nss-db -n "Fake CA" -t C,, -i $<
show-nssdb-ca: nss-db/cert8.db
	$(CERTUTIL) -d nss-db -L -n "Fake CA"
show-nssdb: nss-db/cert8.db
	$(CERTUTIL) -d nss-db -L

###########################################
# Certificate generation rules.
###########################################
certs:
	mkdir -p $@
certs/%.ascii: tbs/%.tbs ca/fake-ca.private.pem scripts/tbs2cert | certs
	scripts/tbs2cert -I tbs/fragment -p ca/fake-ca.private.pem $< > $@
certs/%.der: certs/%.ascii
	ascii2der -i $< -o $@
certs/%.pem: certs/%.der
	$(OPENSSL) x509 -in $< -inform der -out $@
certs/%.chain.pem: certs/%.pem ca/fake-ca.cert
	cat $< ca/fake-ca.cert > $@


###########################################
# Tidy-up.
###########################################
clean:
	rm -f *.ascii
	rm -f *.pyc
	rm -f *.chain.pem
	rm -rf results

distclean: clean
	rm -rf ca
	rm -rf certs
	rm -rf nss-db

.SECONDARY:  # Keep intermediates
