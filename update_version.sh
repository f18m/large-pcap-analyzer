#!/bin/bash

set -u

CURR_VER="$1"
NEW_VER="$2"

for file in configure.ac snap/snapcraft.yaml spec/large-pcap-analyzer.spec; do
	echo "Updating version $CURR_VER -> $NEW_VER in $file"
	sed -i "s@$CURR_VER@$NEW_VER@" $file 
done
