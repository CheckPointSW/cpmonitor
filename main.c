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
#include <getopt.h>

//BUILDNUMBER should be increased manually each commit
#ifndef BUILDNUMBER
#define BUILDNUMBER 8
#endif

/*
These macros are the standard way of turning unquoted text into C strings.
This help in reading the build number added by the BCC in unquoted format
and convert it into C string.
*/
#define STRING(a)  #a
#define TO_STRING(s) STRING(s)

#define MAX_CONN_TABLE_SIZE	200000000

static BOOL is_exit_after_parse_args = FALSE;

static int version_flag = 0;
static struct option long_options[] =
{
	{ "version", no_argument, &version_flag, 1 },
	{ 0, 0, 0, 0 }
};

void usage() {
	/* [-d] flag is available as well, but intended for debug only so it is unofficial */
	/* [-i <interval>] flag was removed since it wasn't used (probably was left over from the kernel mode) */
	PRINTF(
			"\ncpmonitor usage:\n"
			"  cpmonitor [ flags ] <name_of_traffic_dump_file>\n"
		"  cpmonitor [--version] [-v] [-q] [-n] [-o <output>] [-g <graph>] [-t <name>]\n"
		"  [-s <p | t>] [-c <connection table size>] </path_to/name_of_traffic_dump_file>\n"
			"  --version				Display cpmonitor version number\n"
			"					(and exit)\n"
			"  -v					Verbose mode\n"
			"  -q					Quiet mode, no output on stdout,\n"
			"					prints only to output file(s)\n"
			"  -n					Navigates through dump file\n"
			"  -o </path_to/output>			Creates output file\n"
			"					</path_to/output>.txt for the report\n"
			"  -g </path_to/graph>			Creates a timeline graph\n"
			"					and prints it to </path_to/graph>.csv\n"
			"  -t <name>				Prints the entire tables to\n"
			"					</path_to/name>_<table_name>.csv\n"
			"					(e.g.: </path_to/name>_conns.csv)\n"
			"  -s <p | t>				Sets sorting method for top entities:\n"
			"					 p - for packet sorting (default),\n"
			"					 t - for throughput sorting\n"
			"  -c <Size of Connections Table>	Sets size of Connections Table -\n"
			"					an integer number of entries\n"
			"					that the Connections Table can hold\n"
			"					(default is 10,000,000,\n"
			"					max is 200,000,000)\n"
			"  </path_to/name_of_traffic_dump_file>	Path to the traffic capture file\n"
			"					to be analyzed\n\n\n"
		);		
}


int parse_args(int argc, char** argv)
{
	int c = 0;
	int option_index = -1;

	/* get flags from the user */
	while ((c = getopt_long(argc, argv, "dhvqno:g:s:t:c:?", long_options, &option_index)) != -1) {
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
				if (0 != open_file(NULL, cpmonitor_conf.report_name, "txt", &cpmonitor_conf.report_file)) {
					PRINTE("Failed opening the output file.\n\n\n");
					return (-1);
				}
				else {
					is_report_file_open = TRUE;
				}
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
					PRINTE("Invalid sort method (p for packets, t for throughput)\n\n\n");
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
				if ((cpmonitor_conf.connection_table_size <= 0) || (cpmonitor_conf.connection_table_size > MAX_CONN_TABLE_SIZE))
				{
					PRINTE("Invalid connection table size\n");
					usage();
					return (-1);
				}
				PRINTV("parse_args: -c %u\n", cpmonitor_conf.connection_table_size);
				break;
			}
			case 0:
				PRINTV("parse_args: received long flag option: %s\n", long_options[option_index].name);
				if (version_flag) {
					is_exit_after_parse_args = TRUE;
				}
				break;
			/* help/default */
			default:
				PRINTE("Invalid argument '%s'\n", optarg);
		 	case 'h':
		 	case '?':
				is_exit_after_parse_args = TRUE;
				PRINTV("parse_args: -?\n");	
				usage();
				return 0;
         }	
	}

	PRINT("This is open source cpmonitor build #%s\n\n", TO_STRING(BUILDNUMBER));

	if (!version_flag) {
		/* get dump name */
		if (argc - optind == 1) {
			cpmonitor_conf.dump_name = argv[optind];
			PRINTV("parse_args: dump_name: %s\n", cpmonitor_conf.dump_name);
		}
		else {
			if (argc - optind == 0) {
				PRINTE("dump name is missing\n\n\n");
			}
			else {
				PRINTE("too many arguments\n\n\n");
			}
			return (-1);
		}

		if (cpmonitor_conf.report_name == NULL && cpmonitor_conf.graph_name == NULL && cpmonitor_conf.table_file_prefix_name == NULL && cpmonitor_conf.quiet == 1)
		{
			PRINTE("-q and no output file(s) don't go together\n\n\n");
			usage();
			return (-1);
		}
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
		is_report_file_open = FALSE;
		ret = parse_args(argc, argv);

#if __x86_64__
	PRINT("Warning: cpmonitor does not currently support 64 bit. Please run on a 32 bit machine.\n");
#endif

		if ((ret == 0) && (!is_exit_after_parse_args)) {
			ret = dump_main();
		}
	}

	return ret;
}


