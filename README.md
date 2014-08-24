# cpmonitor

This repository contains the source code for the cpmonitor - dump analysing tool.


## Description

cpmonoitor is a standalone utility designed to diagnose traffic captured by [tcpdump](www.tcpdump.org)/[snoop](http://snoopwpf.codeplex.com/).

cpmonitor shows top connections, services and hosts per second, and allows you to navigate through the dump file. 


## Usage

    cpmonitor [ flags ] <dump_file_name>

    Available flags: [-v] [-q] [-n] [-o <output.txt>] [-g <graph.csv>] [-t <name>] [-sort <flag>]

      -v     : verbose
      -q     : quiet, no stdout, only print to output file(s)
      -n     : navigate through dump file
      -o     : create output file <output.txt> for the report
      -g     : create a timeline graph and print to <graph.csv>
      -sort  : set top entries sorting method, <flags> 'p' for packet sorting(default) or 't' for throughput sorting
      -t     : print the entire tables to <name>_conns.csv, <name>_hosts.csv and <name>_services.csv`
  
  
## Compilation

cpmonitor should be compiled on a Linux machine.

cpmonitor needs to be compile with [glib-2.0](https://developer.gnome.org/glib/).

1. run "make"
2. cpmonitor binary file will be created in main directory


## Troubleshooting

####"fatal error: glib.h: No such file or directory"

problem: glib is missing

solution: install glib on the machine: install: "sudo apt-get install libglib2.0-dev"
