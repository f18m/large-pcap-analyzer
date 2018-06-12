# Process this file with autoreconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([large-pcap-analyzer], [3.5.1], [francesco.montorsi@gmail.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debug build; default is release]),[enable_debug=$enableval],[enable_debug=no])

# do not get the -g -O2 default CFLAGS:
: ${CFLAGS=""}
: ${CXXFLAGS=""}



# handle debug/release build
common_flags="-Wall -Wextra -Werror"

# useful for debug builds:
debug_flags="$common_flags -g -O0 -DDEBUG"
release_flags="$common_flags -O3"

AC_MSG_CHECKING([for debug build mode])
AS_IF([test "x$enable_debug" = "xyes"], [
	CXXFLAGS="$CXXFLAGS $debug_flags"
	AC_MSG_RESULT([debug mode enabled])
], [
	CXXFLAGS="$CXXFLAGS $release_flags"
	AC_MSG_RESULT([release mode enabled])
])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11([noext], [optional])

AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live], [], [echo "PCAP library not found. Aborting." ; exit 1])

# Checks for header files.
AC_CHECK_HEADER([pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
