#!/bin/bash
####################################################################
## Simple testing of large_pcap_analyzer
####################################################################

lpa_binary=../large_pcap_analyzer

function test_timing()
{
	echo "Testing -t option..."
	$lpa_binary -t timing-test.pcap | grep -q "0.50pps"
	if [ $? -ne 0 ]; then echo "Failed test of timing analysis (-t option)" ; exit 1 ; fi
}

function test_tcpdump_filter()
{
	echo "Testing -Y option... comparing large_pcap_analyzer and tcpdump"
	test_file[1]=ipv4_ftp.pcap
	pcap_filter[1]="vlan and host 192.168.101.153 and port 1074 and host 10.4.72.4 and port 21"
	test_file[2]=ipv4_gtpu_fragmented.pcap
	pcap_filter[2]="host 36.36.36.8"
	
	for testnum in $(seq 1 2); do
		$lpa_binary -w /tmp/filter${testnum}-lpa.pcap -Y "${pcap_filter[testnum]}" ${test_file[testnum]} >/dev/null
		if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-Y option)" ; exit 1 ; fi
		
		tcpdump -w /tmp/filter${testnum}-tcpdump.pcap -r ${test_file[testnum]}   "${pcap_filter[testnum]}" >/dev/null 2>&1
		if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-Y option)" ; exit 1 ; fi
		
		cmp --silent /tmp/filter${testnum}-lpa.pcap /tmp/filter${testnum}-tcpdump.pcap
		if [ $? -ne 0 ]; then echo "large_pcap_analyzer and tcpdump produced different output (-Y option)" ; exit 1 ; fi
		
		echo "  ... testcase #$testnum passed."
	done
}

function test_gtpu_filter()
{
	echo "Testing -G option... comparing large_pcap_analyzer and tshark"
	
	# test extraction of a specific flow
	test_file[1]=ipv4_gtpu_https.pcap
	pcap_filter[1]="host 10.85.73.237 && port 49789 && host 202.122.145.141 && port 443"
	tshark_filter[1]="ip.addr==10.85.73.237 && tcp.port==49789 && ip.addr==202.122.145.141 && tcp.port==443"
	tshark_dissect_opt[1]=""
	
	# test changing a little bit the syntax of the filter
	test_file[2]=ipv4_gtpu_https.pcap
	pcap_filter[2]="host 10.85.73.237 and host 202.122.145.141 && port 49789 && port 443"
	tshark_filter[2]="${tshark_filter[1]}"
	tshark_dissect_opt[2]=""
	
	test_file[3]=ipv4_gtpu_https.pcap
	pcap_filter[3]="(host 10.85.73.237 and host 202.122.145.141) && (port 49789 && port 443)"
	tshark_filter[3]="${tshark_filter[1]}"
	tshark_dissect_opt[3]=""
				
	# test TCP protocol filtering over tunnel
	test_file[4]=ipv4_gtpu_https.pcap
	pcap_filter[4]="tcp"
	tshark_filter[4]="gtp && ip.proto == 6"
	tshark_dissect_opt[4]=""

	# test handling of fragmented packets
	test_file[5]=ipv4_gtpu_fragmented.pcap
	pcap_filter[5]="host 100.2.1.11 && port 1616 && host 37.37.37.61 && port 80"
	tshark_filter[5]="ip.addr==100.2.1.11 && tcp.port==1616 && ip.addr==37.37.37.61 && tcp.port==80"
	tshark_dissect_opt[5]="-o ip.defragment:FALSE"     # this is needed or otherwise tshark will save into output reassembled IP packets!
		
			
	rm /tmp/filter*
	for testnum in $(seq 1 5); do
		$lpa_binary -w /tmp/filter${testnum}-lpa.pcap -G "${pcap_filter[testnum]}" ${test_file[testnum]} >/dev/null
		if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi
		
		tshark -F pcap -w /tmp/filter${testnum}-tshark.pcap -r ${test_file[testnum]}  ${tshark_dissect_opt[testnum]}  "${tshark_filter[testnum]}" >/dev/null 2>&1
		if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi
		
		cmp --silent /tmp/filter${testnum}-lpa.pcap /tmp/filter${testnum}-tshark.pcap
		if [ $? -ne 0 ]; then echo "large_pcap_analyzer and tshark produced different output (-G option); check /tmp/filter${testnum}-lpa.pcap and /tmp/filter${testnum}-tshark.pcap" ; exit 1 ; fi
		
		echo "  ... testcase #$testnum passed."
	done
}

function test_tcp_filter()
{
	echo "Testing -T option... comparing large_pcap_analyzer and tshark"
	
	# test extraction of conns with SYN
	test_file[1]=ipv4_ftp.pcap
	tcp_filter[1]="syn"
	tshark_filter[1]="tcp.stream eq 1 || tcp.stream eq 2"    # check with tshark that flows 1 & 2 are those having a SYN; flow 0 has not

	test_file[2]=ipv4_ftp.pcap
	tcp_filter[2]="full3way"
	tshark_filter[2]="tcp.stream eq 1 || tcp.stream eq 2"    # check with tshark that flows 1 & 2 are those having a SYN; flow 0 has not

	test_file[3]=ipv4_ftp.pcap
	tcp_filter[3]="full3way-data"
	tshark_filter[3]="tcp.stream eq 1 || tcp.stream eq 2"    # check with tshark that flows 1 & 2 are those having a SYN; flow 0 has not
	
	# ipv4_tcp_flags.pcap is an ad-hoc PCAP that contains the full 3way handshake but no actual data, just ACKs/PSH TCP packets
	test_file[4]=ipv4_tcp_flags.pcap
	tcp_filter[4]="full3way-data"
	tshark_filter[4]="tcp.stream eq 1000"			# this is just a non-existing TCP flow: the output must be empty
		
	rm /tmp/filter*
	for testnum in $(seq 1 4); do
		$lpa_binary -w /tmp/filter${testnum}-lpa.pcap -T "${tcp_filter[testnum]}" ${test_file[testnum]} >/dev/null
		if [ $? -ne 0 ]; then echo "Failed test of TCP filter (-T option)" ; exit 1 ; fi
		
		tshark -F pcap -w /tmp/filter${testnum}-tshark.pcap -r ${test_file[testnum]}   "${tshark_filter[testnum]}" >/dev/null 2>&1
		if [ $? -ne 0 ]; then echo "Failed test of TCP filter (-T option)" ; exit 1 ; fi
		
		cmp --silent /tmp/filter${testnum}-lpa.pcap /tmp/filter${testnum}-tshark.pcap
		if [ $? -ne 0 ]; then echo "large_pcap_analyzer and tshark produced different output (-G option); check /tmp/filter${testnum}-lpa.pcap and /tmp/filter${testnum}-tshark.pcap" ; exit 1 ; fi
		
		echo "  ... testcase #$testnum passed."
	done
}


test_timing
test_tcpdump_filter
test_gtpu_filter
test_tcp_filter
echo "All tests passed successfully"