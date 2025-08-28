

# this ugly hack necessitated by Ubuntu... grrr...
SYSPREFIX=$(shell python3 -c 'import site;print(site.getsitepackages()[0])' | sed -e 's|/[^/]\+/[^/]\+/[^/]\+$$||')
# try to find the architecture-neutral lib dir by looking for one of our expected prereqs... double grrr...
PYLIBDIR=$(shell python3 -c 'import site;import os.path;print([d for d in site.getsitepackages() if os.path.exists(d+"/globus_sdk")][0])')

CONFDIR=/etc
SHAREDIR=$(SYSPREFIX)/share/webauthn2

ifeq ($(wildcard /etc/httpd/conf.d),/etc/httpd/conf.d)
	HTTPSVC=httpd
else
	HTTPSVC=apache2
endif

HTTPDCONFDIR=/etc/$(HTTPSVC)/conf.d
WSGISOCKETPREFIX=/var/run/$(HTTPSVC)/wsgi
DAEMONUSER=webauthn

# turn off annoying built-ins
.SUFFIXES:

INSTALL_SCRIPT=./install-script

install-core: samples/wsgi_webauthn2.conf force
	pip3 install --upgrade .

install-module:
	$(MAKE) -C apache_module install

# make this the default target
install: install-core install-module

testvars: force
	@echo DAEMONUSER=$(DAEMONUSER)
	@echo CONFDIR=$(CONFDIR)
	@echo SYSPREFIX=$(SYSPREFIX)
	@echo SHAREDIR=$(SHAREDIR)
	@echo HTTPDCONFDIR=$(HTTPDCONFDIR)
	@echo WSGISOCKETPREFIX=$(WSGISOCKETPREFIX)
	@echo PYLIBDIR=$(PYLIBDIR)

deploy-core: install-core
	env SHAREDIR=$(SHAREDIR) HTTPDCONFDIR=$(HTTPDCONFDIR) webauthn2-deploy

deploy-module:
	$(MAKE) -C apache_module deploy

deploy: deploy-core deploy-module

samples/wsgi_webauthn2.conf: samples/wsgi_webauthn2.conf.in force
	./install-script -M sed -R @PYLIBDIR@=$(PYLIBDIR) @WSGISOCKETPREFIX@=$(WSGISOCKETPREFIX) @DAEMONUSER@=$(DAEMONUSER) -o root -g root -m a+r -p -D $< $@

uninstall: force
	pip3 uninstall -y webauthn2


preinstall_centos: force
	yum -y install python3 python3-psycopg2 python3-dateutil libcurl libcurl-devel httpd-devel
	pip install globus-sdk

preinstall_ubuntu: force
	apt-get -y install python
	pip install globus-sdk

force:

