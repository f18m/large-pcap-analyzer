## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = large-pcap-analyzer.c


common_flags = -std=c99  -Wall -Wextra 

# useful for debug builds:
#large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) $(common_flags) -g -O0 -DDEBUG

# release builds:
large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) $(common_flags) -O3
