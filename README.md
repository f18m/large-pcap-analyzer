# Large PCAP file analyzer
Large PCAP file analyzer is a command-line utility program that performs some simple operations
on .PCAP files very quickly. This allows you to manipulate also very large PCAP files 
that cannot be easily handled with other software like <a href="https://www.wireshark.org/">Wireshark</a>.

Currently it builds and works on Linux but actually nothing prevents it from running on Windows.
It is based over the well-known libpcap.

Some features of this utility: 

0. Extract packets matching a simple BPF filter.
0. Extract packets matching plain text.
0. Tells you the tcpreplay speed required to respect packet timestamps.


# Command line help

<tt>
    large-pcap-analyzer [-o dumpfile.pcap] [-f filter] [-s string] [-h] somefile.pcap [other pcap files]
    by Francesco Montorsi, (c) Nov 2014
    version 3.1

    Help:
    -h                   this help
    -o <dumpfile.pcap>   where to save the PCAP containing the results of filtering
    -f <pcap-filter>     the PCAP filter to use to produce the dumpfile, see http://www.manpagez.com/man/7/pcap-filter/
    -s <search-string>   an additional filter for packet payloads
    somefile.pcap        the large PCAP to analyze (you can provide more than 1 file)
</tt>


# Example run 1

In this example we are interested in understanding how many seconds of traffic are contained in a PCAP file:

<tt>
    $ ./large-pcap-analyzer large.pcap 

    Analyzing PCAP file 'large.pcap'...
    The PCAP file has size 1.95GiB = 2000MiB.
    No PCAP filter set: all packets inside the PCAP will be loaded.
    Processing took 5 seconds.
    0M packets (844495 packets) were loaded from PCAP.
    Last packet has a timestamp offset = 38.03sec = 0.63min = 0.01hours
    Bytes loaded from PCAP = 941293kiB = 919MiB; total bytes on wire = 941293kiB = 919MiB
      => the whole traffic has been captured in this PCAP!
    Tcpreplay should replay this PCAP at an average of 193.34Mbps / 22205.13pps to respect PCAP timings!
</tt>

Note that to load a 2GB PCAP only 5secs were required (on a 3GHz Intel Xeon CPU).
RAM memory consumption was about 4MB.


# Example run 2

In this example we are interested in selecting any packet that may contain inside it the string "youtube":

<tt>
    $ ./large-pcap-analyzer -s "youtube" -o out.pcap large2.pcap 

    Analyzing PCAP file 'large2.pcap'...
    The PCAP file has size 1.95GiB = 2000MiB.
    No PCAP filter set: all packets inside the PCAP will be loaded.
    Successfully opened output dump PCAP 'out.pcap' in APPEND mode
    1M packets loaded from PCAP...
    2M packets loaded from PCAP...
    3M packets loaded from PCAP...
    Processing took 10 seconds.
    3M packets (3986339 packets) were loaded from PCAP.
    1776 packets matched the search string 'youtube'.
    1776 packets written to the PCAP dump file.
    Last packet has a timestamp offset = 109.14sec = 1.82min = 0.03hours
    Bytes loaded from PCAP = 1985713kiB = 1939MiB; total bytes on wire = 1985713kiB = 1939MiB
      => the whole traffic has been captured in this PCAP!
    Tcpreplay should replay this PCAP at an average of 142.14Mbps / 36526.14pps to respect PCAP timings!
</tt>

Note that to load, search and extract packets from a 2GB PCAP only 10secs were required (on a 3GHz Intel Xeon CPU).
RAM memory consumption was about 4MB.


# Example run 3

In this example we are interested in selecting packets having a VLAN tag and directed or coming from an HTTP server:

<tt>
    $ ./large-pcap-analyzer -f 'vlan and tcp port 80' -o out.pcap large3.pcap

    Analyzing PCAP file 'large3.pcap'...
    The PCAP file has size 1.95GiB = 2000MiB.
    Successfully set PCAP filter: vlan and tcp port 80
    Successfully opened output dump PCAP 'out.pcap' in APPEND mode
    Processing took 1 seconds.
    0M packets (865955 packets) were loaded from PCAP (matching PCAP filter).
    865955 packets written to the PCAP dump file.
    Last packet has a timestamp offset = 109.14sec = 1.82min = 0.03hours
    Bytes loaded from PCAP = 629328kiB = 614MiB; total bytes on wire = 629328kiB = 614MiB
      => the whole traffic has been captured in this PCAP!
    Tcpreplay should replay this PCAP at an average of 45.04Mbps / 7934.63pps to respect PCAP timings!
</tt>

Note that to load, search and extract packets from a 2GB PCAP only 1sec was required (on a 3GHz Intel Xeon CPU).
RAM memory consumption was about 4MB.


