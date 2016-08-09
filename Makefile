

# this ugly hack necessitated by Ubuntu... grrr...
SYSPREFIX=$(shell python -c 'import site;print site.getsitepackages()[0]' | sed -e 's|/[^/]\+/[^/]\+/[^/]\+$$||')
# try to find the architecture-neutral lib dir by looking for one of our expected prereqs... double grrr...
PYLIBDIR=$(shell python -c 'import site;import os.path;print [d for d in site.getsitepackages() if os.path.exists(d+"/web")][0]')

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

UNINSTALL_DIRS=$(PYLIBDIR)/webauthn \
	$(PYLIBDIR)/webauthn/providers \
	$(SHAREDIR) \
	$(VARLIBDIR)

UNINSTALL=$(UNINSTALL_DIRS) \
	$(BINDIR)/webauthn-db-init \
	$(BINDIR)/webauthn-manage

# make this the default target
install: samples/wsgi_webauthn2.conf force
	python ./setup.py install
	$(MAKE) -C apache_module install

testvars: force
	@echo DAEMONUSER=$(DAEMONUSER)
	@echo CONFDIR=$(CONFDIR)
	@echo SYSPREFIX=$(SYSPREFIX)
	@echo SHAREDIR=$(SHAREDIR)
	@echo HTTPDCONFDIR=$(HTTPDCONFDIR)
	@echo WSGISOCKETPREFIX=$(WSGISOCKETPREFIX)
	@echo PYLIBDIR=$(PYLIBDIR)

deploy: install
	env SHAREDIR=$(SHAREDIR) HTTPDCONFDIR=$(HTTPDCONFDIR) webauthn2-deploy
	$(MAKE) -C apache_module deploy

samples/wsgi_webauthn2.conf: samples/wsgi_webauthn2.conf.in
	./install-script -M sed -R @PYLIBDIR@=$(PYLIBDIR) @WSGISOCKETPREFIX@=$(WSGISOCKETPREFIX) @DAEMONUSER@=$(DAEMONUSER) -o root -g root -m a+r -p -D $< $@

# HACK: distutils doesn't have an uninstaller...
uninstall: force
	rm -rf $(UNINSTALL)
	rmdir --ignore-fail-on-non-empty -p $(UNINSTALL_DIRS)

preinstall_centos: force
	yum -y install python python-psycopg2 python-dateutil python-webpy pytz

preinstall_ubuntu: force
	apt-get -y install python python-psycopg2 python-dateutil python-webpy python-tz

force:

