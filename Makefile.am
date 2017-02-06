## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = large-pcap-analyzer.c

# useful for debug builds:
#large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) -Wall -Wextra -g -O0

# release builds:
large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) -Wall -Wextra -O3
