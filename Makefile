
SYSPREFIX=$(shell python -c 'import sys;print sys.prefix')
PYLIBDIR=$(shell python -c 'import distutils.sysconfig;print distutils.sysconfig.get_python_lib()')

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

deploy: install
	webauthn2-deploy
	service httpd restart

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

