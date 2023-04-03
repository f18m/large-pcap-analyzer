## Process this file with automake to produce Makefile.in

# avoid warnings about this packet not being in GNU style:
AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = large_pcap_analyzer
large_pcap_analyzer_SOURCES = \
	src/filter.cpp \
	src/large-pcap-analyzer.cpp \
	src/parse.cpp \
	src/pcap_helpers.cpp \
	src/printf_helpers.cpp \
	src/process_file.cpp \
	src/timestamp_pkt_processor.cpp
large_pcap_analyzer_HDRS = \
	src/config.h \
	src/filter.h \
	src/large-pcap-analyzer.h \
	src/packet.h \
	src/parse.h \
	src/pcap_helpers.h \
	src/printf_helpers.h \
	src/processor.h \
	src/timestamp_pkt_processor.h

check: $(bin_PROGRAMS)
	cd test-pcaps && chmod a+x ./run_tests.sh && bash run_tests.sh

# "test" or "tests" are just synonyms of "check"
test: check
tests: check

distclean:
	rm -f Makefile config.log config.status src/.dirstamp src/config.h src/stamp-h1
	rm -rf autom4te.cache snap/.snapcraft src/.deps

# Note that currently there is no enforcement (for build to be successful) of the code formatting but
# the project adheres to the formatting defined in the .clang-format file
reformat:
	for s in $(large_pcap_analyzer_SOURCES) $(large_pcap_analyzer_HDRS); do \
		clang-format -i $$s ; \
	done


#  this is the MANUAL way to upload a new SNAP but it will be uploaded only for amd64 architecture!
release_new_version:
	snap remove large-pcap-analyzer                                 # in case it was already installed
	snapcraft                                                       # this will rebuild the snap using snap/snapcraft.yaml
	snap install large-pcap-analyzer_*_amd64.snap --devmode         # test new snap installation
	snap list                                                       # confirm new version is now installed
	snapcraft login                                                 # this is interactive and will ask email & password
	snapcraft push --release=stable large-pcap-analyzer_*_amd64.snap   # release upstream
