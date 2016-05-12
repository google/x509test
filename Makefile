all:

tls-src:
	cd tls && $(MAKE) src
tls-bld: tls-src
	cd tls && $(MAKE)

# 'I don't make the rules, I just enforce them with merciless efficiency'
