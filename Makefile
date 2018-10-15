MAKE	= make
SCP		= scp
SSH		= ssh

SCPOPTS	= -r
REMOTE	= bhaskar@basha.attlocal.net

DIRS	= doc src test
IDIRS	= $(DIRS:%=install-%)
CDIRS	= $(DIRS:%=clean-%)

.PHONY: make-dirs $(DIRS)
.PHONY: make-dirs $(IDIRS)
.PHONY: install
.PHONY: make-dirs $(CDIRS)
.PHONY: clean

make-dirs: $(DIRS)

install: $(IDIRS)

clean: $(CDIRS)

$(DIRS):
	$(MAKE) -C $@

$(IDIRS):
	$(MAKE) -C $(@:install-%=%) install

$(CDIRS):
	$(MAKE) -C $(@:clean-%=%) clean

test: src

push:
	$(SCP) $(SCPOPTS) * $(REMOTE):~/src/filestat/
	$(SSH) $(REMOTE) "cd ~/src/filestat && make clean && make"
