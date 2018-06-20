TESTS = qske_newhope_tests

check_PROGRAMS = $(TESTS)

qske_newhope_tests_SOURCES = \
	suites/test_qske_newhope.c \
	suites/test_qske_newhope_noise.c \
	suites/test_qske_newhope_reconciliation.c \
	qske_newhope_tests.h qske_newhope_tests.c

qske_newhope_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/math/libnttfft \
	-I$(top_srcdir)/src/libstrongswan/plugins/qske_newhope \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	@COVERAGE_CFLAGS@

qske_newhope_tests_LDFLAGS = @COVERAGE_LDFLAGS@
qske_newhope_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	$(top_builddir)/src/libstrongswan/math/libnttfft/libnttfft.la \
	../libqske-newhope.la
