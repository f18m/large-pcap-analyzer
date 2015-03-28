#!/bin/bash

# config
destfolder=/usr/bin
outfilename="large-pcap-analyzer"

# compile
make
RETVAL=$?

if [[ $RETVAL = 0 ]]; then
   # installing
   echo Compiled successfully... installing in $destfolder
   cp $outfilename $destfolder
else
   echo Compilation failed. Cannot install.
   echo Note that if gcc gave you errors about pcap.h, maybe you should do
   echo "    apt-get install libpcap-dev"
   echo or something similar for your distro
fi
