# Large PCAP file analyzer
Large PCAP file analyzer is a command-line utility program that performs some simple operations
on .PCAP files very quickly. This allows you to manipulate also very large PCAP files 
that cannot be easily handled with other software like <a href="https://www.wireshark.org/">Wireshark</a>.

Currently it builds and works on Linux but actually nothing prevents it from running on Windows.
It is based over the well-known libpcap.

Some features of this utility: 

1. Extract packets matching a simple BPF filter (tcpdump syntax).
2. Extract packets matching plain text.
3. Computes the tcpreplay speed required to respect packet timestamps.
4. Understands GTPu tunnelling and allows filtering via BPF filters (tcpdump syntax) the encapsulated (inner) GTPu frames.
5. Change PCAP duration, changing the timestamp inside each packet.


# How to install

As for most Linux software, you can install the software just running:

```
	$ wget https://github.com/f18m/large-pcap-analyzer/archive/3.4.3.tar.gz
	$ tar xvzf 3.4.3.tar.gz
	$ cd large-pcap-analyzer-3.4.3/
	$ ./configure && make
	$ sudo make install
```

Or you can use one of the following installation options:

| Build Status  | Applies to |
|:-------------:|:----------:|
| [![RPM Repositories](https://copr.fedorainfracloud.org/coprs/f18m/large-pcap-analyzer/package/large-pcap-analyzer/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/f18m/large-pcap-analyzer/) &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | CentOS 7,  Fedora 27,  Fedora 28, openSUSE Leap 15.0 and openSUSE Tumbleweed. Click on the badge to reach the page with the RPM repository informations. |
| [![Snap Status](https://build.snapcraft.io/badge/f18m/large-pcap-analyzer.svg)](https://snapcraft.io/large-pcap-analyzer) | Arch Linux, Debian, Fedora, Gentoo, Linux Mint, openSUSE, Raspbian, Ubuntu. If you have [snapd](https://docs.snapcraft.io/core/install) installed, just run ```snap install large-pcap-analyzer``` |

For developers: link to [Snapcraft page for large PCAP analyzer](https://build.snapcraft.io/user/f18m/large-pcap-analyzer)


# Command line help

```
	large-pcap-analyzer version 3.5.0
	by Francesco Montorsi, (c) 2014-2018
	Usage:
	  large-pcap-analyzer [options] somefile.pcap ...
	Miscellaneous options:
	 -h,--help                this help
	 -v,--verbose             be verbose
	 -t,--timing              provide timestamp analysis on loaded packets
	 -p,--stats               provide basic parsing statistics on loaded packets
	 -a,--append              open output file in APPEND mode instead of TRUNCATE
	 -w <outfile.pcap>
	 --write <outfile.pcap>   where to save the PCAP containing the results of filtering
	Filtering options (to select packets to save in outfile.pcap):
	 -Y <tcpdump_filter>, --display-filter <tcpdump_filter>
	                          the PCAP filter to apply on packets (will be applied on outer IP frames for GTPu pkts)
	 -G <gtpu_tcpdump_filter>, --inner-filter <gtpu_tcpdump_filter>
	                          the PCAP filter to apply on inner/encapsulated GTPu frames (or outer IP frames for non-GTPu pkts)
	 -C <conn_filter>, --connection-filter <conn_filter>
	                          4-tuple identifying a connection to filter; syntax is 'IP1:port1 IP2:port2'
	 -S <search-string>, --string-filter <search-string>
	                          a string filter that will be searched inside loaded packets
	 -T <syn|full3way|full3way-data>, --tcp-filter  <syn|full3way|full3way-data>
	                          filter for entire TCP connections having 
	                            -T syn: at least 1 SYN packet
	                            -T full3way: the full 3way handshake
	                            -T full3way-data: the full 3way handshake and data packets
	Processing options (changes that will be done on packets selected for output):
	 --set-duration <HH:MM:SS>
	                          alters packet timestamps so that the time difference between first and last packet
	                          matches the given amount of time. All packets in the middle will be equally spaced in time.
	Inputs:
	 somefile.pcap            the large PCAP to analyze (you can provide more than 1 file)
	
	Note that the -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax.
	See http://www.manpagez.com/man/7/pcap-filter/ for more info.
	Other PCAP utilities you may be looking for are:
	 * mergecap: to merge PCAP files
	 * tcpdump: can be used to split PCAP files (and more)
	 * editcap: can be used to manipulate timestamps in PCAP files (and more)
	 * tcprewrite: can be used to rewrite some packet fields in PCAP files (and more)
```

# Example run 1: time analysis

In this example we are interested in understanding how many seconds of traffic are contained in a PCAP file:

```
$ large_pcap_analyzer -t large.pcap 

No PCAP filter set: all packets inside the PCAP will be loaded.
8M packets (8751268 packets) were loaded from PCAP.
Tcpreplay should replay this PCAP at an average of 73.34Mbps / 14580.72pps to respect PCAP timings.
```

Note that to load a 5.6GB PCAP only 1.9secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 3GB/sec (in this mode).
RAM memory consumption was about 4MB.


# Example run 2: raw search

In this example we are interested in selecting any packet that may contain inside it the string "youtube":

```
$ large_pcap_analyzer -v -S "youtube" -w out.pcap bigcapture.pcap

Analyzing PCAP file 'bigcapture.pcap'...
The PCAP file has size 5.50GiB = 5636MiB.
No PCAP filter set: all packets inside the PCAP will be loaded.
Successfully opened output PCAP 'out.pcap'
1M packets loaded from PCAP...
2M packets loaded from PCAP...
3M packets loaded from PCAP...
4M packets loaded from PCAP...
5M packets loaded from PCAP...
6M packets loaded from PCAP...
7M packets loaded from PCAP...
8M packets loaded from PCAP...
Processing took 5 seconds.
8M packets (8751268 packets) were loaded from PCAP.
0M packets (9825 packets) matched the filtering criteria (search string / PCAP filters / valid TCP streams filter) and were saved into output PCAP.
```

Note that to load, search and extract packets from a 5.6GB PCAP only 5secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 1GB/sec (in this mode).
RAM memory consumption was about 4MB.


# Example run 3: tcpdump-like

In this example we are interested in selecting packets having a VLAN tag and directed or coming from an HTTP server:

```
$ large_pcap_analyzer -v -Y 'vlan and tcp port 80' -w out.pcap bigcapture.pcap

Successfully compiled PCAP filter: vlan and tcp port 80
Analyzing PCAP file 'bigcapture.pcap'...
The PCAP file has size 5.50GiB = 5636MiB.
Successfully opened output PCAP 'out.pcap'
1M packets loaded from PCAP (matching PCAP filter)...
2M packets loaded from PCAP (matching PCAP filter)...
3M packets loaded from PCAP (matching PCAP filter)...
4M packets loaded from PCAP (matching PCAP filter)...
5M packets loaded from PCAP (matching PCAP filter)...
6M packets loaded from PCAP (matching PCAP filter)...
7M packets loaded from PCAP (matching PCAP filter)...
8M packets loaded from PCAP (matching PCAP filter)...
Processing took 3 seconds.
8M packets (8751268 packets) were loaded from PCAP (matching PCAP filter).
0M packets (1147 packets) matched the filtering criteria (search string / PCAP filters / valid TCP streams filter) and were saved into output PCAP.
```

Note that to load, search and extract packets from a 2GB PCAP only 1sec was required (on a 3GHz Intel Xeon CPU).
RAM memory consumption was about 4MB.


# Example run 4: GTPu filtering

In this example we are interested in selecting packets GTPu-encapsulated for a specific TCP flow between the
IP address 1.1.1.1 <-> 1.1.1.2, on TCP ports 80 <-> 10000:


```
$ large_pcap_analyzer -v -G '(host 1.1.1.1 or host 1.1.1.2) and (port 80 or port 10000)' -w out.pcap bigcapture.pcap

Successfully compiled GTPu PCAP filter: (host 1.1.1.1 or host 1.1.1.2) and (port 80 or port 10000)
Analyzing PCAP file 'bigcapture.pcap'...
The PCAP file has size 5.50GiB = 5636MiB.
Successfully opened output PCAP 'out.pcap'
1M packets loaded from PCAP...
2M packets loaded from PCAP...
3M packets loaded from PCAP...
4M packets loaded from PCAP...
5M packets loaded from PCAP...
6M packets loaded from PCAP...
7M packets loaded from PCAP...
8M packets loaded from PCAP...
Processing took 3 seconds.
8M packets (8751268 packets) were loaded from PCAP.
8M packets (8501213 packets) loaded from PCAP are GTPu packets (97.1%).
0M packets (0 packets) matched the filtering criteria (search string / PCAP filters / valid TCP streams filter) and were saved into output PCAP.
```


# Example run 5: valid TCP stream filtering

In this example we are interested in selecting packets of TCP connections that have at least 1 SYN and 1 SYN-ACK packet
(if GTPu packets are found this analysis is done for the encapsulated TCP connections):

```
$ large_pcap_analyzer -v -T -w out.pcap bigcapture.pcap

Analyzing PCAP file 'bigcapture.pcap'...
The PCAP file has size 5.50GiB = 5636MiB.
Successfully opened output PCAP 'out.pcap'
Valid TCP filtering enabled: performing first pass
1M packets loaded from PCAP...
2M packets loaded from PCAP...
3M packets loaded from PCAP...
4M packets loaded from PCAP...
5M packets loaded from PCAP...
6M packets loaded from PCAP...
7M packets loaded from PCAP...
8M packets loaded from PCAP...
Processing took 2 seconds.
Detected 1 invalid packets, 721214 non-TCP packets and 37436 valid TCP flows (on a total of 85878 flows).
Valid TCP filtering enabled: performing second pass
Analyzing PCAP file 'bigcapture.pcap'...
The PCAP file has size 5.50GiB = 5636MiB.
1M packets loaded from PCAP...
2M packets loaded from PCAP...
3M packets loaded from PCAP...
4M packets loaded from PCAP...
5M packets loaded from PCAP...
6M packets loaded from PCAP...
7M packets loaded from PCAP...
8M packets loaded from PCAP...
Processing took 2 seconds.
8M packets (8751268 packets) were loaded from PCAP.
0M packets (4498 packets) matched the filtering criteria (search string / PCAP filters / valid TCP streams filter) and were saved into output PCAP.
```

Note that to load, search and extract packets from a 5.6GB PCAP only 4.5secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 1GB/sec (in this mode).


# Example run 6: set PCAP duration

In this example a PCAP that would take 8 minutes to be replayed (without top speed option) will be
modified to take just 1.2 seconds to replay:

```
$ large_pcap_analyzer --timing test-pcaps/ipv4_gtpu_https.pcap
0M packets (18201 packets) were loaded from PCAP.
Last packet has a timestamp offset = 473.48sec = 7.89min = 0.13hours
Tcpreplay should replay this PCAP at an average of 0.27Mbps / 38.44pps to respect PCAP timings.

$ large_pcap_analyzer --set-duration 1.2 --write /tmp/test.pcap test-pcaps/ipv4_gtpu_https.pcap 
PCAP duration will be set to: 1.200000 secs
Successfully opened output PCAP '/tmp/test.pcap'
Packet processing operations require 2 passes: performing first pass
0M packets (18201 packets) were loaded from PCAP.
Packet processing operations require 2 passes: performing second pass
0M packets (18201 packets) were loaded from PCAP.
0M packets (18201 packets) were processed and saved into output PCAP.

$ large_pcap_analyzer --timing /tmp/test.pcap 
0M packets (18201 packets) were loaded from PCAP.
Last packet has a timestamp offset = 1.20sec = 0.02min = 0.00hours
Tcpreplay should replay this PCAP at an average of 105.00Mbps / 15167.50pps to respect PCAP timings.
```
