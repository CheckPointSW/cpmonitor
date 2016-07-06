/*
*   Copyright 2014 Check Point Software Technologies LTD
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*/

#include "core.h"
#include "dump.h"
#include <pcap.h>


void usage() {
	/* [-d] flag is available as well, but intended for debug only so it is unofficial */
	/* [-i <interval>] flag was removed since it wasn't used (probably was left over from the kernel mode) */
	PRINTF(
			"Analyzing dump files mode usage:\n"
			"  cpmonitor [ flags ] <dump_file_name>\n"
			"Available flags: [-v] [-q] [-n] [-o <output.txt>] [-g <graph.csv>] [-t <name>] [-s <method>] [-c <connection table size>]\n"
			"  -v     : verbose\n"
			"  -q     : quiet, no stdout, only print to output file(s)\n"
			"  -n     : navigate through dump file\n"
			"  -o     : create output file <output.txt> for the report\n"
			"  -g     : create a timeline graph and print to <graph.csv>\n"
			"  -t     : print the entire tables to <name>_<table name>.csv (for example: <name>_conns.csv)\n"
			"  -s     : set top entities sorting method, <method> 'p' for packet sorting(default) or 't' fot throghput sorting\n"
			"  -c     : connection table size (an integer, defaut is 10k)\n\n  "
		);		
}


int parse_args(int argc, char** argv)
{
	int c = 0;

	/* get flags from the user */
	while ((c = getopt(argc, argv, "dhvqno:g:s:t:c:?")) != -1) {
         switch (c) {
			/* verbose */
			/* should be first so that all parse_args messages will be outed when the flag is used */
         	case 'v':
				cpmonitor_conf.verbose = 1;
				PRINTV("parse_args: -v\n");	
				break;
			/* debug */
			case 'd':
				cpmonitor_conf.debug = 1;
				PRINTV("parse_args: -d\n");
				break;
			/* quiet */
			case 'q':
				cpmonitor_conf.quiet = 1;
				PRINTV("parse_args: -q\n");
				break;
			/* navigate */
			case 'n':
				cpmonitor_conf.nav = 1;
				PRINTV("parse_args: -n\n");
				break;
			/* output file */
			case 'o':
				cpmonitor_conf.report_name = optarg;
				PRINTV("parse_args: -o %s\n", cpmonitor_conf.report_name);
				break;
			/* timeline graph */
			case 'g':
				cpmonitor_conf.graph_name = optarg;
				PRINTV("parse_args: -g %s\n", cpmonitor_conf.graph_name);
				break;
			/* sort method */
			case 's':
			{
				char *sort_method = optarg;
				if(*sort_method == 'p') {
					cpmonitor_conf.sort_method = sort_method_packets;
					PRINTV("parse_args: -s p\n");
				}
				else if(*sort_method == 't') {
					cpmonitor_conf.sort_method = sort_method_throughput;
					PRINTV("parse_args: -s t\n");
				}
				else {
					PRINTE("Invalid sort method (p for packets, t for throughput)\n");
					return (-1);
				}
				break;
			}
			/* entire tables */
			case 't':
				cpmonitor_conf.table_file_prefix_name = optarg;
				PRINTV("parse_args: -t %s\n", cpmonitor_conf.table_file_prefix_name);
				break;
			/* connection table size */
			case 'c':
			{
				cpmonitor_conf.connection_table_size = atol(optarg);
				if (cpmonitor_conf.connection_table_size <= 0) 
				{
					PRINTE("Error with the connection table size %d\n", cpmonitor_conf.connection_table_size);
					usage();
					return (-1);
				}
				PRINTV("parse_args: -c %u\n", cpmonitor_conf.connection_table_size);
				break;
			}
			/* help/default */
			default:
				PRINTE("Error with the argument '%s'\n", optarg);
		 	case 'h':
		 	case '?':
				PRINTV("parse_args: -?\n");	
				usage();
				return 0;
         }	
	}

	/* get dump name */
	if (argc - optind == 1) {
		cpmonitor_conf.dump_name = argv[optind];
		PRINTV("parse_args: dump_name: %s\n", cpmonitor_conf.dump_name);
    } else {
	    if (argc - optind == 0) {
	    	PRINTE("dump name is missing\n");
	    } else {
			PRINTE("too many arguments\n");			
		}
		return (-1);
    }

	if (cpmonitor_conf.report_name == NULL && cpmonitor_conf.graph_name == NULL && cpmonitor_conf.table_file_prefix_name == NULL && cpmonitor_conf.quiet == 1)
	{
		PRINTE("-q and no output file(s) don't go together\n");
		usage();
		return (-1);
	}

	return 0;
}


int main(int argc, char** argv) 
{
	int ret = 0;

	if (argc < 2) {
		usage();
	}
	else {
		ret = parse_args(argc, argv);

#if __x86_64__
	FPRINTF("Warning: cpmonitor does not currently support 64 bit. Please run on a 32 bit machine.\n");
#endif

		if (ret == 0) {
			ret = dump_main();
		}
	}

	return ret;
}


