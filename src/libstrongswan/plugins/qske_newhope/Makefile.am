AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/math/libnttfft

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES = libqske-newhope.la
libqske_newhope_la_SOURCES = \
	qske_newhope.h qske_newhope.c \
	qske_newhope_noise.h qske_newhope_noise.c \
	qske_newhope_reconciliation.h qske_newhope_reconciliation.c

libqske_newhope_la_LIBADD = \
	$(top_builddir)/src/libstrongswan/math/libnttfft/libnttfft.la

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-qske-newhope.la
else
plugin_LTLIBRARIES = libstrongswan-qske-newhope.la
endif

libstrongswan_qske_newhope_la_SOURCES = \
	qske_newhope_plugin.h qske_newhope_plugin.c

libstrongswan_qske_newhope_la_LDFLAGS = -module -avoid-version

libstrongswan_qske_newhope_la_LIBADD = libqske-newhope.la
