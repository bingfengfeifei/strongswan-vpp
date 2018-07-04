TESTS = oqs_tests

check_PROGRAMS = $(TESTS)

oqs_tests_SOURCES = \
	suites/test_oqs.c suites/test_oqs_kat.c \
	suites/test_oqs_kat_newhope_l1.h \
	suites/test_oqs_kat_newhope_l5.h \
	suites/test_oqs_kat_frodo_aes_l1.h \
	suites/test_oqs_kat_frodo_aes_l3.h \
	suites/test_oqs_kat_frodo_shake_l1.h \
	suites/test_oqs_kat_frodo_shake_l3.h \
	suites/test_oqs_kat_kyber_l1.h \
	suites/test_oqs_kat_kyber_l3.h \
	suites/test_oqs_kat_kyber_l5.h \
	suites/test_oqs_kat_bike1_l1.h \
	suites/test_oqs_kat_bike1_l3.h \
	suites/test_oqs_kat_bike1_l5.h \
	suites/test_oqs_kat_bike2_l1.h \
	suites/test_oqs_kat_bike2_l3.h \
	suites/test_oqs_kat_bike2_l5.h \
	suites/test_oqs_kat_bike3_l1.h \
	suites/test_oqs_kat_bike3_l3.h \
	suites/test_oqs_kat_bike3_l5.h \
	suites/test_oqs_kat_sike_l1.h \
	suites/test_oqs_kat_sike_l3.h \
	suites/test_oqs_kat_saber_l1.h \
	suites/test_oqs_kat_saber_l3.h \
	suites/test_oqs_kat_saber_l5.h \
	suites/test_oqs_kat_lima_2p_l3.h \
	suites/test_oqs_kat_lima_2p_l5.h \
	suites/test_oqs_kat_lima_sp_l1.h \
	suites/test_oqs_kat_lima_sp_l2.h \
	suites/test_oqs_kat_lima_sp_l3.h \
	suites/test_oqs_kat_lima_sp_l5.h \
	oqs_tests.h oqs_tests.c

oqs_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/plugins/oqs \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	@COVERAGE_CFLAGS@

oqs_tests_LDFLAGS = @COVERAGE_LDFLAGS@
oqs_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	../libqske-oqs.la
