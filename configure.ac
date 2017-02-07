# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([large-pcap-analyzer], [3.2], [francesco.montorsi@gmail.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE

# do not get the -g -O2 default CFLAGS:
: ${CFLAGS=""}
: ${CXXFLAGS=""}

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live], [], [echo "PCAP library not found. Aborting." ; exit 1])

# Checks for header files.
AC_CHECK_HEADER([pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset])

#AC_SUBST(_am_dep_true)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
