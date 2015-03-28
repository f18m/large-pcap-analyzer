#
#  Large PCAP files analyzer
#  F. Montorsi
#  
#  Small utility to analyze quickly large PCAP files
#

DEBUG = 1

#-------------------------------------------------------------------------
# Directories
#-------------------------------------------------------------------------
OBJDIR          = ./obj
PCAP_LIBDIR     = .
PCAP_INCDIR     = 

#-------------------------------------------------------------------------
# Build Target Definitions
#-------------------------------------------------------------------------
TARGETNAME     := large-pcap-analyzer
TARGETDESC      = "Large PCAP Analyzer"
TARGETSRC       = large-pcap-analyzer.c
TARGETDEPS      = 
TARGETOBJ       = $(TARGETSRC:.c=.o)

PCAPLIB 	=  -Wl,-Bstatic $(PCAP_LIBDIR)/libpcap.a -Wl,-Bdynamic

#-------------------------------------------------------------------------
# Compiler Options
#-------------------------------------------------------------------------
CFLAGS_DEFS     = -Wall -Wundef -Wextra -D_FILE_OFFSET_BITS=64
CFLAGS_DBG     = -g -O0
CFLAGS_REL     = -O3
ifdef DEBUG
CFLAGS_OPTS    += $(CFLAGS_DBG)
else
CFLAGS_OPTS    += $(CFLAGS_REL)
endif
CFLAGS          = $(CFLAGS_OPTS) $(CFLAGS_DEFS)

#-------------------------------------------------------------------------
# Debug vs. Release Versions
#-------------------------------------------------------------------------
ifdef DEBUG
BUILDMSG 	= "- DEBUG Build"
else
BUILDMSG 	= "- RELEASE Build"
endif

#-------------------------------------------------------------------------
# Build Rules
#-------------------------------------------------------------------------
.c.o :
	@echo "$<"
	$(CC) $(CFLAGS) -o $(OBJDIR)/$(@F) -c $<

#-------------------------------------------------------------------------
# Target Build Dependencies
#-------------------------------------------------------------------------

$(TARGETNAME): preproc $(TARGETDEPS) $(TARGETOBJ)
	@echo "Building ./$@"
	$(CC) $(CFLAGS_OPTS) -o $(TARGETNAME) $(foreach file,$(TARGETOBJ),$(OBJDIR)/$(notdir $(file))) $(PCAPLIB)
	@echo

all: $(TARGETNAME)

preproc: 
	@echo ""
	@echo "Building the $(TARGETDESC) $(BUILDMSG)"
	@echo "-------------------------------------------------------------------------"
	@if [ ! -d "$(OBJDIR)" ]; then mkdir $(OBJDIR); fi

clean: 
	@echo ""
	@echo "Cleaning the $(TARGETDESC) build tree"
	@echo "-------------------------------------------------------------------------"
	rm -Rf $(OBJDIR)/*.o $(TARGETNAME) 
	@echo "Clean build complete."
	@echo ""
