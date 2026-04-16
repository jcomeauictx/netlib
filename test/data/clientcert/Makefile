# made from `make` script
SHELL := /bin/sh
MITMCERT := $(HOME)/.mitmproxy/mitmproxy-ca.pem
SUBJ ?= /C=AU/ST=Some-State/O=Internet Widgits Pty Ltd
all: client.pem
%.key:
	# openssl genrsa -out client.key 2048
	openssl genrsa -out $@ 2048
%.req: %.key
	# openssl req -key client.key -new -out client.req
	openssl req -key $< -new -subj "$(SUBJ)" -nodes -out $@
%.crt: %.req %.key %.cnf $(wildcard $(MITMCERT))
	openssl x509 -req -days 365 -in $< -signkey $(word 2, $+) \
	 -out $@ -extfile $(word 3, $+) -extensions ssl_client
	if [ "$(word 4, $+)" ]; then \
	 openssl x509 -req -days 1000 -in $< \
	  -CA $(word 4, $+) -CAkey $(word 4, $+) \
	  -set_serial 00001 -out $@ -extensions ssl_client; \
	fi
%.pem: %.key %.crt
	# cat client.key client.crt > client.pem
	cat $+ > $@
%.see: %.pem
	# openssl x509 -text -noout -in client.pem
	openssl x509 -text -noout -in $<
.PRECIOUS: %.key %.req %.crt %.pem
