SUBJ ?= /C=NZ/ST=Otago/L=Dunedin/O=netlib/OU=netlib/CN=netlib
all: server.see
%.crt %.key:
	openssl req \
	 -x509 \
	 -newkey rsa:4096 \
	 -keyout $(@:.crt=.key) \
	 -out $@ \
	 -sha256 \
	 -days 3650 \
	 -nodes \
	 -subj "$(SUBJ)"
%.see: %.crt
	openssl x509 \
	 -in $< \
	 -noout \
	 -text
.PRECIOUS: %.crt %.key
