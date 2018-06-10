## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = src/large-pcap-analyzer.cpp src/filter.cpp src/parse.cpp src/processor.cpp src/pcap_helpers.cpp

check: $(bin_PROGRAMS)
	cd test-pcaps && ./run_tests.sh
	
