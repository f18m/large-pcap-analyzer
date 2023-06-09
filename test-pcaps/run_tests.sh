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

function assert_file_contains()
{
    local FILE="$1"
    local EXPECTED_CONTENT="$2"

    grep -q "$EXPECTED_CONTENT" "$FILE"
    if [ $? -ne 0 ]; then
        echo "Expecting [$EXPECTED_CONTENT] inside [$FILE], but that string/pattern has not been found. Aborting."
        exit 2
    fi
}

function assert_file_contains_expected_number_of_lines()
{
    local FILE="$1"
    local EXPECTED_NUMLINES="$2"

    num_lines=$(wc -l "$FILE" | cut -f1 -d ' ')
    if [ $num_lines -ne $EXPECTED_NUMLINES ]; then 
        echo "Expecting [$EXPECTED_NUMLINES] lines inside [$FILE], but found instead [$num_lines] lines. Aborting."
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
        echo "large_pcap_analyzer and $EXPECTED_PRODUCED_BY produced different outputs: compare $FILE_UNDER_TEST and $FILE_EXPECTED"
        exit 2
    fi
}

function assert_floatingpoint_numbers_match()
{
    local VALUE="$1"
    local EXPECTED="$2"
    local ABS_TOLERANCE="${3:-0}"

    local DIFF1="$(echo "$VALUE - $EXPECTED" | bc -l)"
    if [ "$(echo "$DIFF1 <= $ABS_TOLERANCE" | bc -l)" != "1" ] ; then
        echo "Expecting [$EXPECTED] but found instead [$VALUE]. Their difference is bigger than the tolerance [$ABS_TOLERANCE]. Aborting."
        exit 2
    fi

    local DIFF2="$(echo "$EXPECTED - $VALUE" | bc -l)"
    if [ "$(echo "$DIFF2 <= $ABS_TOLERANCE" | bc -l)" != "1" ] ; then
        echo "Expecting [$EXPECTED] but found instead [$VALUE]. Their difference is bigger than the tolerance [$ABS_TOLERANCE]. Aborting."
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

    echo "For testing using: $lpa_binary"
    echo "For testing using: $tcpdump_binary"
    echo "For testing using: $tshark_binary"
}

####################################################################
## Testing functions
####################################################################

function test_timing()
{
    echo "Testing -t,--timing option..."

    # test short option
    test_file[1]="timing-test.pcap"
    expected_pps[1]="0.50pps"
    expected_duration[1]="60.00"
    expected_exitcode[1]=0
    expected_human_friendly_output_lines[1]=3

    # try to check timing of an invalid PCAP file containing negative timestamps
    test_file[2]="invalid_timestamp1_negative_ts.pcap"
    expected_pps[2]="0"
    expected_duration[2]="0"
    expected_exitcode[2]=2 # we expect a failure in timing analysis
    expected_human_friendly_output_lines[2]=2

    # try to check timing of an invalid PCAP file containing "0" as timestamp for all pkts
    test_file[3]="invalid_timestamp2_zero_ts.pcap"
    expected_pps[3]="0"
    expected_duration[3]="0"
    expected_exitcode[3]=2 # we expect a failure in timing analysis
    expected_human_friendly_output_lines[3]=3

    for testnum in $(seq 1 3); do

        # ---- first test -----
        # check the human-friendly output:
        $lpa_binary -t "${test_file[testnum]}" >/tmp/timing-test-${testnum}
        if [ $? -ne ${expected_exitcode[testnum]} ]; then echo "Failed test of timing analysis (-t option)" ; exit 1 ; fi

        # we should produce a specific number lines:
        assert_file_contains_expected_number_of_lines "/tmp/timing-test-${testnum}" "${expected_human_friendly_output_lines[testnum]}"
        
        # human-friendly output should contain (somewhere) the expected PPS  & expected duration:
        assert_file_contains "/tmp/timing-test-${testnum}" "${expected_pps[testnum]}"
        assert_file_contains "/tmp/timing-test-${testnum}" "${expected_duration[testnum]}"

        # ---- second test -----
        # now analyze again the PCAP using the script-friendly output (--quiet):
        $lpa_binary -q -t "${test_file[testnum]}" >/tmp/timing-test-quiet-${testnum}
        if [ $? -ne ${expected_exitcode[testnum]} ]; then echo "Failed test of timing analysis (-t option)" ; exit 1 ; fi

        if [ ${expected_exitcode[testnum]} -eq 0 ]; then
            # in quiet mode the LPA should always produce just 1 line
            assert_file_contains_expected_number_of_lines "/tmp/timing-test-quiet-${testnum}" "1"

            # that line must contain the duration:
            local actual_duration=$(cat /tmp/timing-test-quiet-${testnum})
            assert_floatingpoint_numbers_match "$actual_duration" "${expected_duration[testnum]}"
        fi
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


    rm -f /tmp/filter*.pcap
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

    rm -f /tmp/filter*.pcap
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

    rm -f /tmp/filter*.pcap
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

    rm -f /tmp/filter*.pcap
    for testnum in $(seq 1 3); do
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --set-duration "${test_duration[testnum]}" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-duration option" ; exit 1 ; fi

        # now validate against the --timing option
        local new_duration="$($lpa_binary -q --timing /tmp/filter${testnum}-lpa.pcap)"
        assert_strings_match "$new_duration" "${expected_timing_output[testnum]}"

        echo "  ... testcase #$testnum passed."
    done
}

function test_set_duration_preserve_ifg()
{
    echo "Testing --set-duration-preserve-ifg option..."

    # original duration is 60sec
    test_file[1]="timing-test.pcap"
    test_scale_factor[1]="10"

    # original duration is 60sec
    test_file[2]="timing-test.pcap"
    test_scale_factor[2]="5"

    # original duration is 60sec
    test_file[3]="timing-test.pcap"
    test_scale_factor[3]="1"

    local -r ts_tolerance_sec="0.0001"

    # in this test we assume that --timing option of LPA works correctly...

    rm -f /tmp/filter*.pcap /tmp/pkts-timings-*
    for testnum in $(seq 1 3); do

        # first of all acquire current duration:
        local curr_duration="$($lpa_binary -q --timing ${test_file[testnum]})"

        # compute new duration:
        local new_duration_computed="$( echo $curr_duration / ${test_scale_factor[testnum]} | bc -l )"

        # run --set-duration-preserve-ifg
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --set-duration-preserve-ifg "$new_duration_computed" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-duration-preserve-ifg option" ; exit 1 ; fi

        # now validate against the --timing option
        local new_duration="$($lpa_binary -q --timing /tmp/filter${testnum}-lpa.pcap)"
        assert_floatingpoint_numbers_match "$new_duration" "$new_duration_computed"

        # extract all pkt timestamps from the ORIGINAL pcap:
        $tshark_binary -F pcap -r ${test_file[testnum]} -Tfields -e frame.time_relative >/tmp/pkts-timings-original-${testnum}.txt 2>/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-duration-preserve-ifg option" ; exit 1 ; fi

        # extract all pkt timestamps from the PROCESSED pcap:
        $tshark_binary -F pcap -r /tmp/filter${testnum}-lpa.pcap -Tfields -e frame.time_relative >/tmp/pkts-timings-scaled-${testnum}.txt 2>/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-duration-preserve-ifg option" ; exit 1 ; fi

        local npkts1="$(wc -l /tmp/pkts-timings-original-${testnum}.txt | cut -f1 -d' ')"
        local npkts2="$(wc -l /tmp/pkts-timings-scaled-${testnum}.txt | cut -f1 -d' ')"
        assert_strings_match "$npkts1" "$npkts2"

        # process each timestamp
        for pktIdx in $(seq 1 $npkts1); do
            local orig_ts="$(sed ${pktIdx}q\;d /tmp/pkts-timings-original-${testnum}.txt)"
            local scaled_ts="$(sed ${pktIdx}q\;d /tmp/pkts-timings-scaled-${testnum}.txt)"

            #echo "$orig_ts -> $scaled_ts"
            local rescaled_ts="$( echo "$scaled_ts * ${test_scale_factor[testnum]}" | bc -l )"
            assert_floatingpoint_numbers_match "$orig_ts" "$rescaled_ts" "$ts_tolerance_sec"
        done

        echo "  ... testcase #$testnum passed."
    done
}

function test_set_timestamps()
{
    echo "Testing --set-timestamps-from option..."

    test_file[1]="timing-test.pcap"
    test_input_timestamps[1]="timestamps-30pkts.txt"
    expected_timing_output[1]="4.000000"
    expected_timestamp_pkt10[1]="1549740001.312413000"

    test_file[2]="ipv4_ftp.pcap"
    test_input_timestamps[2]="timestamps-40470pkts.txt"
    expected_timing_output[2]="18.297805"
    expected_timestamp_pkt10[2]="30.749287000"


    # in this test we assume that --timing option of LPA works correctly...

    rm -f /tmp/filter*.pcap /tmp/pkts-timings-*
    for testnum in $(seq 1 2); do
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --set-timestamps-from "${test_input_timestamps[testnum]}" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-timestamps-from option" ; exit 1 ; fi

        # now validate against the --timing option
        local new_duration="$($lpa_binary -q --timing /tmp/filter${testnum}-lpa.pcap)"
        assert_strings_match "$new_duration" "${expected_timing_output[testnum]}"

        # extract 10-th pkt timestamp:
        $tshark_binary -F pcap -r /tmp/filter${testnum}-lpa.pcap -Tfields -e frame.time_epoch >/tmp/pkts-timings-${testnum}.txt 2>/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --set-timestamps-from option" ; exit 1 ; fi
        local found_timestamp="$(sed '10q;d' /tmp/pkts-timings-${testnum}.txt)"

        # now validate against tshark-extracted timestamp for 10th pkt:
        assert_strings_match "$found_timestamp" "${expected_timestamp_pkt10[testnum]}"

        echo "  ... testcase #$testnum passed."
    done


    # test that providing a wrong number of packets in the input timestamp file will trigger an error printed by the LPA:
    #   we use the timestamps for test file #2 with test file #1:
    $lpa_binary -w /tmp/failtest-lpa.pcap --set-timestamps-from "${test_input_timestamps[2]}" ${test_file[1]} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Failed test of --set-timestamps-from option: expected a failure but instead LPA returned success!"
        exit 1
    fi

    (( testnum++ ))
    echo "  ... testcase #$testnum passed."

    # test again that LPA fails if mismatching number of packets are provided
    #   we use the timestamps for test file #1 with test file #2:
    $lpa_binary -w /tmp/failtest-lpa.pcap --set-timestamps-from "${test_input_timestamps[1]}" ${test_file[2]} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Failed test of --set-timestamps-from option: expected a failure but instead LPA returned success!"
        exit 1
    fi

    (( testnum++ ))
    echo "  ... testcase #$testnum passed."

    # try to use a timestamp file which contains invalid syntax:
    $lpa_binary -w /tmp/failtest-lpa.pcap --set-timestamps-from "test-pcaps/timestamps-invalid.txt" ${test_file[1]} >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Failed test of --set-timestamps-from option: expected a failure but instead LPA returned success!"
        exit 1
    fi

    (( testnum++ ))
    echo "  ... testcase #$testnum passed."
}

function test_reporting_traffic_stats()
{
    echo "Testing --report option..."

    test_file[1]="ipv4_ftp.pcap"
    expected_csv_output[1]="traffic_ipv4_ftp.csv"
    test_file[2]="ipv4_gtpu_https.pcap"
    expected_csv_output[2]="traffic_ipv4_gtpu_https.csv"
    
    rm -f /tmp/filter*.pcap /tmp/traffic-flow-*
    for testnum in $(seq 1 1); do
        # first of all launch the LPA asking it to generate the traffic report on stdout
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --report "allflows_by_pkts" ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --report option" ; exit 1 ; fi

        # now launch again combining with --report-write option
        $lpa_binary -w /tmp/filter${testnum}-lpa.pcap --report "allflows_by_pkts" --report-write /tmp/traffic-flow-${testnum}.csv ${test_file[testnum]} >/dev/null
        if [ $? -ne 0 ]; then echo "Failed test of --report option" ; exit 1 ; fi

        assert_files_match "/tmp/traffic-flow-${testnum}.csv" "${expected_csv_output[testnum]}" "manually"
    done
}


find_dependencies_or_die

# remove any possible PCAP file produced by a previuos run of these tests
rm -f /tmp/*.pcap 

test_timing
#test_tcpdump_filter
#test_gtpu_filter
#test_extract_conn_filter
#test_tcp_filter
#test_set_duration
#test_set_duration_preserve_ifg
#test_set_timestamps
#test_reporting_traffic_stats
echo "All tests passed successfully"

