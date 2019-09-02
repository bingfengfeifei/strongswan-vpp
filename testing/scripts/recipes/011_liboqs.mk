#!/usr/bin/make

PKG = liboqs
ZIP = $(PKG)-master.zip
SRC = https://github.com/open-quantum-safe/$(PKG)/archive/master.zip

all: install

$(ZIP):
	wget --ca-directory="/usr/share/ca-certificates/mozilla" $(SRC) -O $(ZIP)

$(PKG)-master: $(ZIP)
	unzip $(ZIP)

.$(PKG)-built: $(PKG)-master
	cd $(PKG)-master && autoreconf -i && ./configure PREFIX=/usr && make -j $(NUM_CPUS)
	@touch $@

install: .$(PKG)-built
	cd $(PKG)-master && make install
