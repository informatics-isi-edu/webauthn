RELEASE=$(shell svn info  | grep "Revision:" | awk  '{print $$2}')

# arguments that can be set via make target params or environment?
PLATFORM=centos6

# get platform-specific variable bindings
include config/make-vars-$(PLATFORM)

# catalog of all the files/dirs we manage via make targets below
INSTALL_PYTHON_FILES= \
	__init__.py \
	manager.py \
	rest.py \
	util.py \
	exc.py \
	providers/__init__.py \
	providers/crowd2.py \
	providers/database.py \
	providers/null.py \
	providers/oauth1a.py \
	providers/providers.py \
	providers/webcookie.py \
	providers/globusonline.py \
	providers/verified_https.py

INSTALL_PYTHON_DIRS= \
	providers

EDIT_FILES= \
	Makefile \
	webauthn2_config.json \
	$(INSTALL_PYTHON_FILES)

CLEAN_FILES= \
	$(EDIT_FILES:%=%~) \
	$(INSTALL_PYTHON_FILES:%=%c) \
	$(INSTALL_PYTHON_FILES:%=%o) \
	config/*~

# these are the install target contents... actual system file paths
INSTALL_FILES= \
	$(INSTALL_PYTHON_FILES:%=$(PYLIBDIR)/webauthn2/%) \
	$(SHAREDIR)/webauthn2_config.json

INSTALL_DIRS= \
	$(INSTALL_PYTHON_DIRS:%=$(PYLIBDIR)/webauthn2/%)

# bump the revision when changing predeploy side-effects
PREINSTALL=$(VARLIBDIR)/preinstall.r4143

# turn off annoying built-ins
.SUFFIXES:

# make this the default target
install: $(INSTALL_FILES) $(PREINSTALL)

uninstall: force
	rm -f $(INSTALL_FILES)
	rmdir --ignore-fail-on-non-empty -p $(INSTALL_DIRS)

# get platform-specific rules (e.g. actual predeploy recipe)
include config/make-rules-$(PLATFORM)

$(SHAREDIR)/%: %
	install -o root -g root -m a=r -p -D $< $@

$(PYLIBDIR)/webauthn2/%: ./%
	install -o root -g root -m a=rx -p -D $< $@

preinstall: $(PREDEPLOY)

unpreinstall: force
	rm -f $(VARLIBDIR)/preinstall.r*

clean: force
	rm -f $(CLEAN_FILES)

cleanhost: force uninstall unpreinstall

force:

