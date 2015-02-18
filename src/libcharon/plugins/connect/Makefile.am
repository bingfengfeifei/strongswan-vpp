AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_PIDDIR=\"${piddir}\"

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-connect.la
else
plugin_LTLIBRARIES = libstrongswan-connect.la
endif

libstrongswan_connect_la_SOURCES = connect_plugin.h connect_plugin.c \
	connect_socket.h connect_socket.c connect_msg.h

libstrongswan_connect_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = connect
connect_SOURCES = connect.c
connect_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la