## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign subdir-objects

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = src/large-pcap-analyzer.cpp src/filter.cpp src/parse.cpp
common_flags = -Wall -Wextra -Werror

# useful for debug builds:
large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) $(common_flags) -g -O0 -DDEBUG
large_pcap_analyzer_CXXFLAGS = $(AM_CFLAGS) $(common_flags) -g -O0 -DDEBUG

# release builds:
#large_pcap_analyzer_CFLAGS = $(AM_CFLAGS) $(common_flags) -O3
