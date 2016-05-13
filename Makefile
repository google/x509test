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

TBS_FILES = $(subst tbs/,,$(wildcard tbs/*.tbs))

RESULTS_OPENSSL_OK = $(addprefix results/openssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_BORINGSSL_OK = $(addprefix results/boringssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_GNUTLS_OK = $(addprefix results/gnutls/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_NSS_OK = $(addprefix results/nss/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))

RESULTS_OPENSSL_XF = $(addprefix results/openssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_BORINGSSL_XF = $(addprefix results/boringssl/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_GNUTLS_XF = $(addprefix results/gnutls/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))
RESULTS_NSS_XF = $(addprefix results/nss/$(TLS)/,$(subst .tbs,.out, $(TBS_FILES)))

RESULTS_OPENSSL = $(RESULTS_OPENSSL_OK) $(RESULTS_OPENSSL_XF)
# @@@ RESULTS_BORINGSSL = $(RESULTS_BORINGSSL_OK) $(RESULTS_BORINGSSL_XF)
RESULTS_GNUTLS = $(RESULTS_GNUTLS_OK) $(RESULTS_GNUTLS_XF)
RESULTS_NSS = $(RESULTS_NSS_OK) $(RESULTS_NSS_XF)

RESULTS = $(RESULTS_OPENSSL) $(RESULTS_BORINGSSL) $(RESULTS_GNUTLS) $(RESULTS_NSS)

all: check

check: $(RESULTS) check-ok check-xf
check-ok:
	@echo "*** Valid certificates that failed validation:"
	@grep "TLS-VALIDATION: Failed" results/*/$(TLS)/ok-* || true
check-xf:
	@echo "*** Invalid certificates that passed validation:"
	@grep "TLS-VALIDATION: Success" results/*/$(TLS)/xf-* || true
check-openssl: check-openssl-ok check-openssl-xf
check-openssl-ok: $(RESULTS_OPENSSL_OK)
	@echo "*** Valid certificates that failed OpenSSL validation:"
	@grep "TLS-VALIDATION: Failed" results/openssl/$(TLS)/ok-* || true
check-openssl-xf: $(RESULTS_OPENSSL_XF)
	@echo "*** Invalid certificates that passed OpenSSL validation:"
	@grep "TLS-VALIDATION: Success" results/openssl/$(TLS)/xf-* || true
check-boringssl: check-boringssl-ok check-boringssl-xf
check-boringssl-ok: $(RESULTS_BORINGSSL_OK)
	@echo "*** Valid certificates that failed BoringSSL validation:"
	@grep "TLS-VALIDATION: Failed" results/boringssl/$(TLS)/ok-* || true
check-boringssl-xf: $(RESULTS_BORINGSSL_XF)
	@echo "*** Invalid certificates that passed BoringSSL validation:"
	@grep "TLS-VALIDATION: Success" results/boringssl/$(TLS)/xf-* || true
check-gnutls: check-gnutls-ok check-gnutls-xf
check-gnutls-ok: $(RESULTS_GNUTLS_OK)
	@echo "*** Valid certificates that failed GnuTLS validation:"
	@grep "TLS-VALIDATION: Failed" results/gnutls/$(TLS)/ok-* || true
check-gnutls-xf: $(RESULTS_GNUTLS_XF)
	@echo "*** Invalid certificates that passed GnuTLS validation:"
	@grep "TLS-VALIDATION: Success" results/gnutls/$(TLS)/xf-* || true
check-nss: check-nss-ok check-nss-xf
check-nss-ok: $(RESULTS_NSS_OK)
	@echo "*** Valid certificates that failed NSS validation:"
	@grep "TLS-VALIDATION: Failed" results/nss/$(TLS)/ok-* || true
check-nss-xf: $(RESULTS_NSS_XF)
	@echo "*** Invalid certificates that passed NSS validation:"
	@grep "TLS-VALIDATION: Success" results/nss/$(TLS)/xf-* || true

results-openssl: $(RESULTS_OPENSSL)
results-boringssl: $(RESULTS_BORINGSSL)
results-gnutls: $(RESULTS_GNUTLS)
results-nss: $(RESULTS_NSS)

# deps target prepares TLS tools; it depends on the TLS env var.
deps: $(DEPS)
pkg-install:
	sudo apt-get install $(PREREQS)
show-tls:
	@echo Using: $(OPENSSL) $(BORINGSSL) $(CERTUTIL) $(CERTTOOL)

###########################################
# TLS tool targets.
# Manual targets to build local copies.
###########################################
tls-tip-src:
	cd third_party/tip && $(MAKE) src
tls-tip-bld: tls-tip-src
	cd third_party/tip && $(MAKE)
tls-stable-src:
	cd third_party/stable && $(MAKE) src
tls-stable-bld: tls-stable-src
	cd third_party/stable && $(MAKE)


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
results/openssl/$(TLS)/%.out: certs/%.pem ca/fake-ca.cert | results/openssl/$(TLS)
	scripts/check-openssl $(OPENSSL) verify -CAfile ca/fake-ca.cert $< > $@ 2>&1
results/boringssl/$(TLS)/%.out: certs/%.pem ca/fake-ca.cert | results/boringssl/$(TLS)
	scripts/check-boringssl $(BORINGSSL) verify -CAfile ca/fake-ca.cert $< > $@ 2>&1
results/gnutls/$(TLS)/%.out: certs/%.chain.pem ca/fake-ca.cert | results/gnutls/$(TLS)
	scripts/check-certtool $(CERTTOOL) --verify-chain --load-ca-certificate fake-ca.cert --infile $< >$@ 2>&1
results/nss/$(TLS)/%.out: certs/%.pem | results/nss/$(TLS) nss-db/cert8.db
	scripts/check-certutil $(CERTUTIL) $< > $@ 2>&1

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
ca/fake-ca.public.pem: ca/fake-ca.private.pem
	$(OPENSSL) rsa -pubout -in $< -out $@
# Generate a self-signed certificate via a CSR.
SUBJ = /C=GB/ST=London/L=London/O=Google/OU=Eng/CN=FakeCertificateAuthority
ca/fake-ca.csr: ca/fake-ca.private.pem
	$(OPENSSL) req -new  -days 365 -subj $(SUBJ) -inform pem -key $< -out $@
ca/fake-ca.cert: ca/fake-ca.csr ca/fake-ca.private.pem
	$(OPENSSL) x509 -req -days 365 -in ca/fake-ca.csr -signkey ca/fake-ca.private.pem -out $@
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
	scripts/tbs2cert $< ca/fake-ca.private.pem > $@
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
