ACLOCAL_AMFLAGS = -I build-aux/m4

AM_CPPFLAGS =
if NDEBUG
AM_CPPFLAGS += -DNDEBUG
endif
COMMON_CFLAGS := -Wall -Wextra -Wcast-qual -Wconversion -Wdisabled-optimization -Wdouble-promotion -Wno-implicit-fallthrough -Wmissing-declarations -Wno-missing-field-initializers -Wpacked -Wno-parentheses -Wredundant-decls -Wno-sign-conversion $(addprefix -Wsuggest-attribute=,pure const noreturn malloc) -Wno-vla
AM_CFLAGS = $(COMMON_CFLAGS) $(addprefix -Werror=,implicit-function-declaration incompatible-pointer-types int-conversion)
AM_CXXFLAGS = $(COMMON_CFLAGS) -Wnoexcept -Wold-style-cast -Wsign-promo -Wsuggest-override -Wno-terminate -Wzero-as-null-pointer-constant

include_HEADERS = bech32.h

pkgconfig_DATA = libbech32.pc
EXTRA_DIST = $(pkgconfig_DATA)

dist_man_MANS = bech32.1

lib_LTLIBRARIES = libbech32.la
libbech32_la_SOURCES = libbech32.c
if BUILD_CXX
libbech32_la_SOURCES += libbech32_c++.cpp
libbech32_la_LINK = $(CXXLINK) $(libbech32_la_CXXFLAGS) $(libbech32_la_LDFLAGS)
else
libbech32_la_LINK = $(LINK) $(libbech32_la_CFLAGS) $(libbech32_la_LDFLAGS)
endif
# How to update version-info:
# - oldprog+newlib and newprog+oldlib are both okay => +0:+1:+0
# - oldprog+newlib is okay, but newprog+oldlib won't work => +1:=0:+1
# - oldprog+newlib won't work => +1:=0:=0
libbech32_la_LDFLAGS = -no-undefined -version-info 0:0:0

bin_PROGRAMS = bech32
bech32_SOURCES = bech32.c
bech32_LDADD = libbech32.la

if BUILD_TESTS

check_PROGRAMS = test
test_SOURCES = test.cpp
test_CPPFLAGS = $(filter-out -DNDEBUG,$(AM_CPPFLAGS))
test_LDFLAGS = -no-install
test_LDADD = libbech32.la

TESTS = $(check_PROGRAMS)
noinst_PROGRAMS = $(check_PROGRAMS)

else

check-local:
	@! echo "You didn't enable the tests! Run './configure --enable-tests'." >&2

endif # BUILD_TESTS

@DX_RULES@
MOSTLYCLEANFILES = $(DX_CLEANFILES)

if BUILD_MANPAGES
man3_MANS = $(addprefix doxygen-doc/man/man3/,$(addsuffix .3,bech32.h \
	$(shell $(SED) -Ene 's/^((\w|\*)+\s+)+(\w+)\(.*$$/\3/p#)' $(srcdir)/bech32.h)))
$(man3_MANS) : doxygen-doc
$(DX_DOCDIR)/$(PACKAGE).tag : $(include_HEADERS)
endif

install-exec-hook:
	cd $(DESTDIR)$(bindir) && { test -e bech32m$(EXEEXT) || $(LN_S) -n bech32$(EXEEXT) bech32m$(EXEEXT) ; }
	cd $(DESTDIR)$(man1dir) && { test -e bech32m.1 || $(LN_S) -n bech32.1 bech32m.1 ; }

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/bech32m$(EXEEXT)
	rm -f $(DESTDIR)$(man1dir)/bech32m.1
