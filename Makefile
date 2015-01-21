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
	webauthn2/providers/crowd2.py \
	webauthn2/providers/crowdrest1.py \
	webauthn2/providers/database.py \
	webauthn2/providers/null.py \
	webauthn2/providers/oauth1a.py \
	webauthn2/providers/oauth2.py \
	webauthn2/providers/providers.py \
	webauthn2/providers/webcookie.py \
	webauthn2/providers/globusonline.py \
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
	$(SHAREDIR)/webauthn2_config.json

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

$(SHAREDIR)/%: ./samples/%
	install -o root -g root -m u=rw,g=r,o=r -p -D $< $@

$(PYLIBDIR)/%: ./%
	install -o root -g root -m u=rw,g=r,o=r -p -D $< $@

preinstall: $(PREDEPLOY)

unpreinstall: force
	rm -f $(VARLIBDIR)/preinstall.r*

clean: force
	rm -f $(CLEAN_FILES)

cleanhost: force uninstall unpreinstall

force:

