#!/bin/bash

####################################################################
## Simple testing of large_pcap_analyzer
####################################################################

# be robust against typos:
set -uo pipefail

# test the locally-build LPA
lpa_binary="../large_pcap_analyzer"

# other 3rd party binaries we need:
tcpdump_binary="$(which tcpdump)"
tshark_binary="$(which tshark)"


####################################################################
## Helper functions
####################################################################

function assert_strings_match()
{
    local VALUE="$1"
    local EXPECTED="$2"

    if [ "$VALUE" != "$EXPECTED" ] ; then
        echo "Expecting [$EXPECTED] but found instead [$VALUE]. Aborting."
        exit 2
    fi
}

function assert_files_match()
{
    local FILE_UNDER_TEST="$1"
    local FILE_EXPECTED="$2"
    local EXPECTED_PRODUCED_BY="$3"

    cmp --silent "$FILE_UNDER_TEST" "$FILE_EXPECTED"
    if [ $? -ne 0 ]; then
        echo "large_pcap_analyzer and $EXPECTED_PRODUCED_BY produced different outputs"
        exit 2
    fi
}

function find_dependencies_or_die()
{
    if [ ! -x "$lpa_binary" ]; then
        echo "Cannot find the large-pcap-analyzer executable to test!"
        exit 20
    fi
    if [ -z "$tcpdump_binary" ]; then
        echo "Cannot find the tcpdump executable!"
        exit 30
    fi
    if [ -z "$tshark_binary" ]; then
        echo "Cannot find the tshark executable!"
        exit 40
    fi
}

####################################################################
## Testing functions
####################################################################

function test_timing()
{
    echo "Testing -t,--timing option..."

    output[1]="$($lpa_binary -t timing-test.pcap)"
    expected_pps[1]="0.50pps"
    expected_duration[1]="60.00sec"

    output[2]="$($lpa_binary --timing timing-test.pcap)"
    expected_pps[2]="0.50pps"
    expected_duration[2]="60.00sec"

    for testnum in $(seq 1 2); do

        # test that the line that starts as "Tcpreplay should replay this PCAP at an average of"... contains the right PPS
        echo "${output[testnum]}" | grep -q "${expected_pps[testnum]}"
        if [ $? -ne 0 ]; then echo "Failed test of timing analysis (-t option)" ; exit 1 ; fi

        echo "${output[testnum]}" | grep -q "${expected_duration[testnum]}"
        if [ $? -ne 0 ]; then echo "Failed test of timing analysis (-t option)" ; exit 1 ; fi

        echo "  ... testcase #$testnum passed."
    done
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

        $tcpdump_binary -w /tmp/filter${testnum}-tcpdump.pcap -r ${test_file[testnum]}   "${pcap_filter[testnum]}" >/dev/null 2>&1
        if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-Y option)" ; exit 1 ; fi

        assert_files_match "/tmp/filter${testnum}-lpa.pcap" "/tmp/filter${testnum}-tcpdump.pcap" "tcpdump"

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


    rm /tmp/filter*.pcap
    for testnum in $(seq 1 5); do
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap -G "${pcap_filter[testnum]}" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi

        $tshark_binary -F pcap -w /tmp/filter${testnum}-tshark.pcap -r ${test_file[testnum]}  ${tshark_dissect_opt[testnum]}  "${tshark_filter[testnum]}" >/dev/null 2>&1
        if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi

        assert_files_match "/tmp/filter${testnum}-lpa.pcap" "/tmp/filter${testnum}-tshark.pcap" "tshark"

        echo "  ... testcase #$testnum passed."
    done
}

function test_extract_conn_filter()
{
    echo "Testing -G option... comparing large_pcap_analyzer and tshark"

    # test extraction of a specific flow
    test_file[1]=ipv4_gtpu_https.pcap
    conn_filter[1]="10.85.73.237:49789 202.122.145.141:443"
    tshark_filter[1]="ip.addr==10.85.73.237 && tcp.port==49789 && ip.addr==202.122.145.141 && tcp.port==443"
    tshark_dissect_opt[1]=""

    rm /tmp/filter*.pcap
    for testopt in $(seq 1 2); do

        local option="-G"
        if (( testopt == 2 )); then
            # test long option as well
            option="--inner-filter"
        fi

        for testnum in $(seq 1 1); do
            $lpa_binary -w /tmp/filter${testnum}-lpa.pcap $option "${pcap_filter[testnum]}" ${test_file[testnum]} >/dev/null
            if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi

            $tshark_binary -F pcap -w /tmp/filter${testnum}-tshark.pcap -r ${test_file[testnum]}  ${tshark_dissect_opt[testnum]}  "${tshark_filter[testnum]}" >/dev/null 2>&1
            if [ $? -ne 0 ]; then echo "Failed test of PCAP filter (-G option)" ; exit 1 ; fi

            assert_files_match "/tmp/filter${testnum}-lpa.pcap" "/tmp/filter${testnum}-tshark.pcap" "tshark"

            echo "  ... testcase #$testnum with $option passed."
        done
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

    rm /tmp/filter*.pcap
    for testopt in $(seq 1 2); do

        local option="-T"
        if (( testopt == 2 )); then
            # test long option as well
            option="--tcp-filter"
        fi
        for testnum in $(seq 1 4); do
            $lpa_binary -w /tmp/filter${testnum}-lpa.pcap $option "${tcp_filter[testnum]}" ${test_file[testnum]} >/dev/null
            if [ $? -ne 0 ]; then echo "Failed test of TCP filter (-T option)" ; exit 1 ; fi

            $tshark_binary -F pcap -w /tmp/filter${testnum}-tshark.pcap -r ${test_file[testnum]}   "${tshark_filter[testnum]}" >/dev/null 2>&1
            if [ $? -ne 0 ]; then echo "Failed test of TCP filter (-T option)" ; exit 1 ; fi

            assert_files_match "/tmp/filter${testnum}-lpa.pcap" "/tmp/filter${testnum}-tshark.pcap" "tshark"

            echo "  ... testcase #$testnum with $option passed."
        done
    done
}

function test_set_duration()
{
    echo "Testing --set-duration option..."

    # original duration is 60sec
    test_file[1]="timing-test.pcap"
    test_duration[1]="13"
    expected_timing_output[1]="13.000000"

    # original duration is 18.3sec
    test_file[2]="ipv4_ftp.pcap"
    test_duration[2]="100.020"
    expected_timing_output[2]="100.020000"

    # original duration is 18.3sec
    test_file[3]="ipv4_ftp.pcap"
    test_duration[3]="10:09:08.7"			# test different syntax
    expected_timing_output[3]="36548.700000"

    # in this test we assume that --timing option of LPA works correctly...

    rm /tmp/filter*.pcap
    for testnum in $(seq 1 3); do
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --set-duration "${test_duration[testnum]}" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-duration option" ; exit 1 ; fi

        # now validate against the --timing option
        local new_duration="$($lpa_binary -q --timing /tmp/filter${testnum}-lpa.pcap)"
        assert_strings_match "$new_duration" "${expected_timing_output[testnum]}"

        echo "  ... testcase #$testnum passed."
    done
}

function test_set_timestamps()
{
    echo "Testing --set-timestamps option..."

    test_file[1]="timing-test.pcap"
    test_input_timestamps[1]="timestamps-30pkts.txt"
    expected_timing_output[1]="4.000000"
    expected_timestamp_pkt10[1]="1549740001.312413000"

    test_file[2]="ipv4_ftp.pcap"
    test_input_timestamps[2]="timestamps-40470pkts.txt"
    expected_timing_output[2]="18.297805"
    expected_timestamp_pkt10[2]="30.749287000"


    # in this test we assume that --timing option of LPA works correctly...

    rm /tmp/filter*.pcap
    for testnum in $(seq 1 2); do
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --set-timestamps "${test_input_timestamps[testnum]}" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-timestamps option" ; exit 1 ; fi

        # now validate against the --timing option
        local new_duration="$($lpa_binary -q --timing /tmp/filter${testnum}-lpa.pcap)"
        assert_strings_match "$new_duration" "${expected_timing_output[testnum]}"

        # extract 10-th pkt timestamp:
        $tshark_binary -F pcap -r /tmp/filter${testnum}-lpa.pcap -Tfields -e frame.time_epoch >/tmp/pkts-timings-${testnum}.txt 2>/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-timestamps option" ; exit 1 ; fi
        local found_timestamp="$(sed '10q;d' /tmp/pkts-timings-${testnum}.txt)"

        # now validate against tshark-extracted timestamp for 10th pkt:
        assert_strings_match "$found_timestamp" "${expected_timestamp_pkt10[testnum]}"

        echo "  ... testcase #$testnum passed."
    done
}

find_dependencies_or_die
test_timing
test_tcpdump_filter
test_gtpu_filter
test_extract_conn_filter
test_tcp_filter
test_set_duration
test_set_timestamps
echo "All tests passed successfully"


