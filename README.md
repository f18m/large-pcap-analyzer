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
4. Understands GTPu tunnelling and allows filtering via BPF filters (tcpdump syntax) the encapsulated (inner) GTPu frames


# How to install

As for most Linux software, you can install the software just running:

```
	$ wget https://github.com/f18m/large-pcap-analyzer/archive/3.4.2.tar.gz
	$ tar xvzf 3.4.2.tar.gz
	$ cd large-pcap-analyzer-3.4.2/
	$ ./configure && make
	$ sudo make install
```


# Command line help

```
	large_pcap_analyzer `[-h] [-v] [-a] [-w outfile.pcap] [-Y tcpdump_filter] [-G gtpu_tcpdump_filter] [-S string] [-T] somefile.pcap` ...
	by Francesco Montorsi, (c) Nov 2014-2017
	version 3.3
	
	Miscellaneous options:
	 -h                       this help
	 -v                       be verbose
	 -t                       provide timestamp analysis on loaded packets
	 -a                       open output file in APPEND mode instead of TRUNCATE
	 -w <outfile.pcap>        where to save the PCAP containing the results of filtering
	Filtering options:
	 -Y <tcpdump_filter>      the PCAP filter to apply when READING the pcap
	 -G <gtpu_tcpdump_filter> the PCAP filter to apply on inner GTPu frames (if any) to select packets to save in outfile.pcap
	 -S <search-string>       an string filter  to select packets to save in outfile.pcap
	 -T                       select packets part of valid TCP connections, i.e. connections having at least 1 SYN and 1 SYN/ACK
	Inputs:
	 somefile.pcap            the large PCAP to analyze (you can provide more than 1 file)
	Note that the -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax.
	See http://www.manpagez.com/man/7/pcap-filter/ for more info.
```

# Example run 1: time analysis

In this example we are interested in understanding how many seconds of traffic are contained in a PCAP file:

<tt>
	$ large_pcap_analyzer -t large.pcap 
	
	No PCAP filter set: all packets inside the PCAP will be loaded.
	8M packets (8751268 packets) were loaded from PCAP.
	Tcpreplay should replay this PCAP at an average of 73.34Mbps / 14580.72pps to respect PCAP timings.
</tt>

Note that to load a 5.6GB PCAP only 1.9secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 3GB/sec (in this mode).
RAM memory consumption was about 4MB.


# Example run 2: raw search

In this example we are interested in selecting any packet that may contain inside it the string "youtube":

<tt>
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
</tt>

Note that to load, search and extract packets from a 5.6GB PCAP only 5secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 1GB/sec (in this mode).
RAM memory consumption was about 4MB.


# Example run 3: tcpdump-like

In this example we are interested in selecting packets having a VLAN tag and directed or coming from an HTTP server:

<tt>
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
</tt>

Note that to load, search and extract packets from a 2GB PCAP only 1sec was required (on a 3GHz Intel Xeon CPU).
RAM memory consumption was about 4MB.


# Example run 4: GTPu filtering

In this example we are interested in selecting packets GTPu-encapsulated for a specific TCP flow between the
IP address 1.1.1.1 <-> 1.1.1.2, on TCP ports 80 <-> 10000:

<tt>
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
</tt>


# Example run 5: valid TCP stream filtering

In this example we are interested in selecting packets of TCP connections that have at least 1 SYN and 1 SYN-ACK packet
(if GTPu packets are found this analysis is done for the encapsulated TCP connections):

<tt>
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
</tt>

Note that to load, search and extract packets from a 5.6GB PCAP only 4.5secs were required (on a 3GHz Intel Xeon CPU).
This translates to a processing throughput of about 1GB/sec (in this mode).
