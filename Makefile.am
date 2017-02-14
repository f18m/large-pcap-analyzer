## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign subdir-objects

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = src/large-pcap-analyzer.cpp src/filter.cpp src/parse.cpp

check:
	cd test-pcaps && ./run_tests.sh
	
