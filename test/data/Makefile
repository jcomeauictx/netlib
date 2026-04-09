SUBJ ?= /C=NZ/ST=Otago/L=Dunedin/O=netlib/OU=netlib/CN=netlib
all: server.see
%.crt %.key: Makefile
	openssl req \
	 -x509 \
	 -newkey rsa:1024 \
	 -keyout $(@:.crt=.key) \
	 -out $@ \
	 -sha1 \
	 -days 3650 \
	 -nodes \
	 -subj "$(SUBJ)"
%.see: %.crt
	openssl x509 \
	 -in $< \
	 -noout \
	 -text
.PRECIOUS: %.crt %.key
