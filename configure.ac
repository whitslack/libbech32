m4_define([version_major], [1])
m4_define([version_minor], [0])

AC_INIT([libbech32], m4_join([.], [version_major], [version_minor]))
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([build-aux/m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT([disable-static])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_SED
PKG_INSTALLDIR

AC_ARG_ENABLE([assertions],
	[AS_HELP_STRING([--enable-assertions], [check assertions at runtime [default=no]])],
	[enable_assertions=$enableval],
	[enable_assertions=no])
AM_CONDITIONAL([NDEBUG], [test x"$enable_assertions" = xno])

AC_ARG_ENABLE([blech32],
	[AS_HELP_STRING([--disable-blech32], [do not include Blech32 code in the library])],
	[enable_blech32=$enableval],
	[enable_blech32=yes])
AM_CONDITIONAL([DISABLE_BLECH32], [test x"$enable_blech32" = xno])

AC_ARG_ENABLE([c++],
	[AS_HELP_STRING([--disable-c++], [do not include C++ code in the library])],
	[enable_cxx=$enableval],
	[enable_cxx=yes])
AM_CONDITIONAL([BUILD_CXX], [test x"$enable_cxx" = xyes])
AM_COND_IF([BUILD_CXX], [
	AX_CXX_COMPILE_STDCXX([20])
])

AC_ARG_ENABLE([tests],
	[AS_HELP_STRING([--disable-tests], [do not build unit tests [default=enabled if C++ is enabled]])],
	[enable_tests=$enableval],
	[enable_tests=$enable_cxx])
AM_CONDITIONAL([BUILD_TESTS], [test x"$enable_tests" = xyes])
AM_COND_IF([BUILD_TESTS], [
	AM_COND_IF([BUILD_CXX], [], [AC_MSG_ERROR([building tests requires --enable-c++])])
])

DX_DOXYGEN_FEATURE([ON])
DX_HTML_FEATURE([OFF])
DX_MAN_FEATURE([ON])
DX_PDF_FEATURE([OFF])
DX_PS_FEATURE([OFF])
DX_INIT_DOXYGEN([libbech32])
AM_CONDITIONAL([BUILD_MANPAGES], [DX_TEST_FEATURE([man])])

AC_CONFIG_FILES([Makefile libbech32.pc])
AC_OUTPUT
