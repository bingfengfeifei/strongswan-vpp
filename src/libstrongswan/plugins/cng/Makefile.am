AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-cng.la
else
plugin_LTLIBRARIES = libstrongswan-cng.la
endif

libstrongswan_cng_la_SOURCES = \
	cng_hasher.h cng_hasher.c \
	cng_plugin.h cng_plugin.c

libstrongswan_cng_la_LDFLAGS = -module -avoid-version
libstrongswan_cng_la_LIBADD  = -lbcrypt
