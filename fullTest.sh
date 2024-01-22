#!/bin/bash

# Directory containing .pcap and .pcap.out files
directory="./pcap_files"

# Executable that processes .pcap files
executable="./trace"

# Loop through all .pcap files in the directory
for pcap_file in "$directory"/*.pcap; do
    # Check if the .pcap file exists
    if [[ -f "$pcap_file" ]]; then
        # Derive the name of the .pcap.out file
        out_file="${pcap_file%.pcap}.pcap.out"

        # Check if the corresponding .pcap.out file exists
        if [[ -f "$out_file" ]]; then
            echo "Processing: $pcap_file"

            # Run the executable and redirect its output to test.txt
            "$executable" "$pcap_file" > test.txt

            # Run diff to compare the output in test.txt with the .pcap.out file
            diff -B --ignore-all-space test.txt "$out_file"

            # Check the exit status of diff
            if [ $? -eq 0 ]; then
                echo "No differences found for $pcap_file"
            else
                echo "Differences found for $pcap_file"
            fi
        else
            echo "No corresponding .pcap.out file for $pcap_file"
        fi
    else
        echo "$pcap_file does not exist"
    fi
done

# Clean up by removing test.txt
rm -f test.txt
