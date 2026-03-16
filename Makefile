SHELL := /bin/ash
WHICH := type -p
PACKAGE := $(notdir $(PWD))
SCRIPTS := $(shell find . -type f -name '*.py')
LINT := $(SCRIPTS:.py=.pylint)
default: install
	mitmdump --version
install: setup.py build \
 .installed/libxslt-dev .installed/libxml2-dev .installed/gcc \
 .installed/python3-dev .installed/py3-libxml2 .installed/musl-dev \
 .installed/py3-pillow .installed/openssl-dev .installed/libffi-dev \
 .installed/build-base .installed/py3-flask .installed/py3-urwid
	sudo python3 $< $@
build: setup.py clean .FORCE | .installed/python3
	python3 $< $@
# this really isn't necessary until/unless we want to build an apk package
$(HOME)/.abuild: | /etc/alpine-release
	abuild-keygen -an
.installed/python3 .installed/gcc: .installed .FORCE
	if [ "! $(WHICH) $(@F)"	]; then \
	 sudo apk add $(@F); \
	fi
	touch $@
.installed/py3-%: .installed
	sudo apk add $(@F)
	touch $@
.installed:
	mkdir $@
%.pylint: %.py .installed/py3-pylint
	pylint $<
pylint: $(LINT)
pip-install: .installed/py3-pip
	pip --verbose install --force-reinstall \
	 git+https://github.com/jcomeauictx/netlib@$(PACKAGE)-ish
.installed/%-dev .installed/%-base: .installed
	sudo apk add $(@F)
	touch $@
clean:
	sudo rm -rf build dist *.egg_info
	find . -type d -name __pycache__ -exec sudo rm -rf {} +
	find . -name '*.py[co]' -delete
.FORCE:
