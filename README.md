# cpmonitor

This repository contains the source code for the cpmonitor - dump analyzing tool.


## Description

cpmonoitor is a standalone utility designed to diagnose traffic captured by [tcpdump](www.tcpdump.org)/[snoop](http://snoopwpf.codeplex.com/).

cpmonitor shows top connections, services and hosts per second, and allows you to navigate through the dump file. 


## Usage

    cpmonitor [ flags ] <dump_file_name>

    Available flags: [-v] [-q] [-n] [-o <output.txt>] [-g <graph.csv>] [-t <name>] [-s <method>] [-c <connection table size>]

      -v     : verbose
      -q     : quiet, no stdout, only print to output file(s)
      -n     : navigate through dump file
      -o     : create output file <output.txt> for the report
      -g     : create a timeline graph and print to <graph.csv>
      -t     : print the entire tables to <name>_<table name>.csv (for example: <name>_conns.csv)
      -s     : set top entities sorting method, <method> 'p' for packet sorting(default) or 't' fot throghput sorting
      -c     : connection table size (number of entries the connection table can hold, an integer, default is 10,000,000)


	Example:

	Traffic that needs to be analyzed can be captured using the standard Linux tcpdump tool as follows:
		tcpdump -i {<name_of_relevant_interface> | any} -w /var/log/capture.cap

	Run cpmonitor in regular complete mode:
		./cpmonitor /var/log/capture.cap

  
## Compilation

cpmonitor should be compiled on a Linux machine.

cpmonitor needs to be compiled with [glib-2.0](https://developer.gnome.org/glib/).

1. run "make"
2. cpmonitor binary file will be created in main directory


## Troubleshooting

####"fatal error: glib.h: No such file or directory"

problem: glib is missing

solution: install glib on the machine: install: "sudo apt-get install libglib2.0-dev"



####"fatal error: pcap.h: No such file or directory"

problem: libpcap is missing

solution: install libpcap on the machine


## Third party software

cpmonitor uses libpcap version 0.9.4 which is distributed under the 3-clause BSD license.
