#!/usr/bin/make

PKG = liboqs
REV = nist-branch
ZIP = $(PKG)-$(REV).zip
SRC = https://github.com/open-quantum-safe/$(PKG)/archive/$(REV).zip

all: install

$(ZIP):
	wget --ca-directory="/usr/share/ca-certificates/mozilla" $(SRC) -O $(ZIP)

$(PKG)-$(REV): $(ZIP)
	unzip $(ZIP)

.$(PKG)-built-$(REV): $(PKG)-$(REV)
	cd $(PKG)-$(REV) && make -j $(NUM_CPUS)
	@touch $@

install: .$(PKG)-built-$(REV)
	cd $(PKG)-$(REV) && PREFIX=/usr make install
