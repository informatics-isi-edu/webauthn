RELEASE=$(shell svn info  | grep "Revision:" | awk  '{print $$2}')

# arguments that can be set via make target params or environment?
PLATFORM=centos6

# get platform-specific variable bindings
include config/make-vars-$(PLATFORM)

# catalog of all the files/dirs we manage via make targets below
INSTALL_PYTHON_FILES= \
	webauthn2/__init__.py \
	webauthn2/manager.py \
	webauthn2/rest.py \
	webauthn2/util.py \
	webauthn2/exc.py \
	webauthn2/providers/__init__.py \
	webauthn2/providers/database.py \
	webauthn2/providers/goauth.py \
	webauthn2/providers/null.py \
	webauthn2/providers/oauth1a.py \
	webauthn2/providers/oauth2.py \
	webauthn2/providers/providers.py \
	webauthn2/providers/webcookie.py \
	webauthn2/providers/globusonline.py \
	webauthn2/providers/globus_auth.py \
	webauthn2/providers/verified_https.py

INSTALL_PYTHON_DIRS= \
	webauthn2/providers 

EDIT_FILES= \
	Makefile \
	samples/webauthn2_config.json \
	$(INSTALL_PYTHON_FILES)

CLEAN_FILES= \
	$(EDIT_FILES:%=%~) \
	$(INSTALL_PYTHON_FILES:%=%c) \
	$(INSTALL_PYTHON_FILES:%=%o) \
	config/*~

# these are the install target contents... actual system file paths
INSTALL_FILES= \
	$(INSTALL_PYTHON_FILES:%=$(PYLIBDIR)/%) \
	$(SHAREDIR)/samples/database/webauthn2_config.json \
	$(SHAREDIR)/samples/globus_auth/webauthn2_config.json \
	$(SHAREDIR)/samples/globus_auth/client_secret_globus.json \
	$(SHAREDIR)/samples/globus_auth/discovery_globus.json \
	$(SHAREDIR)/samples/goauth/go_config.yml \
	$(SHAREDIR)/samples/goauth/README-goauth \
	$(SHAREDIR)/samples/goauth/webauthn2_config.json \
	$(SHAREDIR)/v2_upgrade/webauthn2_v2_upgrade.sql \
	$(SHAREDIR)/v2_upgrade/webauthn2_v2_upgrade.py \
        $(SBINDIR)/webauthn2-v2-upgrade

INSTALL_DIRS= \
	$(INSTALL_PYTHON_DIRS:%=$(PYLIBDIR)/%)

# bump the revision when changing predeploy side-effects
PREINSTALL=$(VARLIBDIR)/preinstall.r4143

# turn off annoying built-ins
.SUFFIXES:

# make this the default target
install: $(INSTALL_FILES) $(PREINSTALL)

uninstall: force
	rm -f $(INSTALL_FILES)
	rmdir --ignore-fail-on-non-empty -p $(INSTALL_DIRS) $(SHAREDIR)

# get platform-specific rules (e.g. actual predeploy recipe)
include config/make-rules-$(PLATFORM)

$(SHAREDIR)/samples/%: ./samples/%
	install -o root -g root -m u=rw,g=r,o=r -p -D $< $@

$(SHAREDIR)/v2_upgrade/%: ./webauthn2/scripts/v2_upgrade/%
	install -o root -g root -m u=rw,g=r,o=r -p -D $< $@

$(PYLIBDIR)/%: ./%
	install -o root -g root -m u=rw,g=r,o=r -p -D $< $@

$(SBINDIR)/webauthn2-v2-upgrade : ./webauthn2/scripts/v2_upgrade/webauthn2-v2-upgrade
	install -o root -g root -m ugo=rx -p -D $< $@

preinstall: $(PREDEPLOY)

unpreinstall: force
	rm -f $(VARLIBDIR)/preinstall.r*

clean: force
	rm -f $(CLEAN_FILES)

cleanhost: force uninstall unpreinstall

force:

