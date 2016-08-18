### cpmonitor

This repository contains the source code for the cpmonitor - dump analyzing tool.


### Description

cpmonitor is a utility targeted to analyze traffic captured by tcpdump (www.tcpdump.org) / snoop (http://snoopwpf.codeplex.com/).

It parses the input traffic capture file and extracts valuable information from it, including:

	* Overall traffic statistics (pps, cps, concurrent, throughput)
	* Top connections, top servers and top services
	* Detailed connections, servers and services (with packet size distribution)
	* Per second analysis


### Syntax

    # cpmonitor [ flags ] <name_of_traffic_dump_file>

	# cpmonitor [-v] [-q] [-n] [-o <output>] [-g <graph>] [-t <name>] [-s <p | t>] [-c <connection table size>] <name_of_traffic_dump_file>

	where:
	Argument:								Description:
	=========								============
	-v										Verbose mode
	-q										Quiet mode, no output on stdout, prints only to output file(s)
	-n										Navigates through dump file
	-o </path_to/output>					Creates output file </path_to/output>.txt for the report
	-g </path_to/graph>						Creates a timeline graph and prints it to </path_to/graph>.csv
	-t <name>								Prints the entire tables to </path_to/name>_<table_name>.csv (e.g.: </path_to/name>_conns.csv)
	-s <p | t>								Sets sorting method for top entities:
												p - for packet sorting (default)
												t - for throughput sorting
	-c <Size of Connections Table>			Sets size of Connections Table - an integer number of entries that the Connections Table can hold (default is 10,000,000, max is 200,000,000)
	</path_to/name_of_traffic_dump_file>	Path to the traffic capture file to be analyzed


### Usage

Traffic that needs to be analyzed can be captured using the standard Linux tcpdump tool as follows (the default 96 bytes are sufficient):

	# tcpdump -i {<name_of_relevant_interface> | any} -w /var/log/capture.cap

	Notes:
	* To avoid performance impact, instead of capturing the traffic on the involved machine, traffic can be captured on a switch (using SPAN / Mirror port).
	* On machines with complex NIC topology, "tcpdump -i any" syntax should be avoided. Refer to the "Known limitations" section.
	* cpmonitor also supports traffic captured with interface information as follows: 	# tcpdump -Pennni -w /var/log/capture.cap


When analyzing the captured traffic, cpmonitor tool can run in two modes: Complete or Navigate, allowing different insights.

	* Complete mode
	  =============

		# ./cpmonitor <name_of_traffic_capture_file>

	Produces a summary report from the content of the entire traffic capture file.

	Tip: Use with the "-t" flag to produce detailed CSV files containing all the connections, servers and services. This creates a complete picture of the entire traffic (not just the top traffic).


	* Navigate mode
	  =============

		# ./cpmonitor -n <name_of_traffic_capture_file>

	Creates a report for the first second of the traffic capture file and allows to navigate across the file, as well as increase the window size to cover more than one second.

	This mode allows better understanding of traffic bursts and peaks, which may have occurred during the capture.

	Tip: Press "h" for available options when running in navigation mode.


### Third party software

cpmonitor uses libpcap version 0.9.4 which is distributed under the 3-clause BSD license.


### Compilation

cpmonitor should be compiled on a Linux machine.

cpmonitor needs to be compiled with glib-2.0(https://developer.gnome.org/glib/).

Instructions:
	1. Run make.
	2. The cpmonitor binary file will be created in main directory.


### Troubleshooting compilation issues

	1. 	Error: "fatal error: glib.h: No such file or directory"
		Cause: glib is missing
		Solution: install glib on the machine:	# sudo apt-get install libglib2.0-dev"

	2. 	Error: "fatal error: pcap.h: No such file or directory"
		Cause: libpcap is missing
		Solution: install libpcap on the machine
		Install libpcap 0.9.4 on the machine:
			A. Download libpcap-0.9.4 package:
				* If this machine is connected to the Internet:
					# mkdir /var/tmp/libpcap
					# cd /var/tmp/libpcap
					# wget http://www.tcpdump.org/release/libpcap-0.9.4.tar.gz

				* If this is an offline machine:
					Download the package from http://www.tcpdump.org/release/libpcap-0.9.4.tar.gz to your computer and transfer it to the Linux machine (into some directory, e.g., /var/tmp/libpcap/).

			B. Extract the package:
				# cd /var/tmp/libpcap
				# tar -zxvf libpcap-0.9.4.tar.gz

			C. Prepare and install the package:
				# ./configure
				# make
				# make install

			D. Copy the documentation:
				# install -v -m755 -d /usr/share/doc/libpcap-0.9.4
				# install -v -m644 doc/*{html,txt} /usr/share/doc/libpcap-0.9.4

			E. Verify that libpcap files were installed / copied:
				# find / -name *libpcap* -type f


### Known limitations

	* cpmonitor is not supported on 64-bit based OS.
	The following message will be displayed:
		"Warning: cpmonitor does not currently support 64 bit. Please run on a 32 bit machine."

	* When traffic is captured on a machine with complex NIC topology using the syntax: # tcpdump -i any
	the capture file will hold multiple entries for each packet (an entry for each interface in the packet's path).
	cpmonitor does not currently support identifying multiple entries of the same packet.
	Analyzing such a capture file using cpmonitor might result in wrong statistics.
	This issue can be resolved by using multiple captures for individual interfaces using the syntax: # tcpdump -i <name_of_relevant_interface>
