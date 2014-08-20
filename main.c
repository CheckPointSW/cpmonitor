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

void usage() {
	PRINTF(
			"Analyzing dump files mode usage:\n"
			"  cpmonitor [ flags ] <dump_file_name>\n"
			"Available flags: [-v] [-q] [-n] [-o <output.txt>] [-g <graph.csv>] [-t <name>] [-s <method>] [-i <interval>] [-c <connection table size>]\n"
			"  -v     : verbose\n"
			"  -q     : quiet, no stdout, only print to output file(s)\n"
			"  -n     : navigate through dump file\n"
			"  -o     : create output file <output.txt> for the report\n"
			"  -g     : create a timeline graph and print to <graph.csv>\n"
			"  -s     : set top enteties sorting method, <method> 'p' for packet sorting(default) or 't' fot throghput sorting\n"
			"  -t     : print the entire tables to <name>_conns.csv, <name>_hosts.csv and <name>_services.csv\n"			
			"  -c     : connection table size (an integer, defaut is 10k)\n\n  "
		);		
}


void parse_args(int argc, char** argv)
{
	int c;

	/* get flags from the user */
	while ((c = getopt(argc, argv, "hvqno:g:s:t:c:?")) != -1) {
         switch (c) {
			/* verbode */
         	case 'v':
				cpmonitor_conf.verbose = 1;
				PRINTV("parse_args: -v\n");	
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
					exit(-1);
				}
				break;
			}
			/* entire tables */
			case 't':
				cpmonitor_conf.table_name = optarg;
				PRINTV("parse_args: -t %s\n", cpmonitor_conf.table_name);
				break;
			/* connection table size */
			case 'c':
			{
				cpmonitor_conf.connection_table_size = atol(optarg);
				if (cpmonitor_conf.connection_table_size <= 0) 
				{
					PRINTE("Error with the connection table size %d\n", cpmonitor_conf.connection_table_size);
					usage();
					exit(-1);
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
				exit(0);
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
		exit(-1);
    }

	if (cpmonitor_conf.report_name == NULL && cpmonitor_conf.graph_name == NULL && cpmonitor_conf.table_name == NULL && cpmonitor_conf.quiet == 1) 
	{
		PRINTE("-q and no output file(s) don't go together\n");
		usage();
		exit(-1);
	}
}

void close_files() {

	if (cpmonitor_conf.report_file) {
		fclose(cpmonitor_conf.report_file);
		cpmonitor_conf.report_file = NULL;
	}
			
	if (cpmonitor_conf.graph_file) {
		fclose(cpmonitor_conf.graph_file);
	}

	if (cpmonitor_conf.table_conns_file) {
		fclose(cpmonitor_conf.table_conns_file);
	}
	
	if (cpmonitor_conf.table_hosts_file) {
		fclose(cpmonitor_conf.table_hosts_file);
	}
	
	if (cpmonitor_conf.table_services_file) {
		fclose(cpmonitor_conf.table_services_file);
	}
}

int open_files() 
{
	char csv_name[1024];
	
	if (cpmonitor_conf.report_name) {
		cpmonitor_conf.report_file = fopen(cpmonitor_conf.report_name, "w");
		if (cpmonitor_conf.report_file == NULL) {
			PRINTE("failed to open report file %s\n", cpmonitor_conf.report_name);
			goto fail;
		}
	}

	
	if (cpmonitor_conf.graph_name) {
		cpmonitor_conf.graph_file = fopen(cpmonitor_conf.graph_name, "w");
		if (cpmonitor_conf.graph_file == NULL) {
			PRINTE("failed to open graph file %s\n", cpmonitor_conf.graph_name);
			goto fail;
		}
	}

	if (cpmonitor_conf.table_name) {
		snprintf(csv_name, sizeof(csv_name), "%s_conns.csv", cpmonitor_conf.table_name);
		cpmonitor_conf.table_conns_file = fopen(csv_name, "w");
		if (cpmonitor_conf.table_conns_file == NULL) {
			PRINTE("failed to open connetion table file %s\n", csv_name);
			goto fail;
		}
		
		snprintf(csv_name, sizeof(csv_name), "%s_hosts.csv", cpmonitor_conf.table_name);
		cpmonitor_conf.table_hosts_file = fopen(csv_name, "w");
		if (cpmonitor_conf.table_hosts_file == NULL) {
			PRINTE("failed to open host table file %s\n", csv_name);			
			goto fail;
		}
		
		snprintf(csv_name, sizeof(csv_name), "%s_services.csv", cpmonitor_conf.table_name);
		cpmonitor_conf.table_services_file = fopen(csv_name, "w");
		if (cpmonitor_conf.table_services_file == NULL) {
			PRINTE("failed to open services table file %s\n", csv_name);
			goto fail;
		}		
	}

	return 0;
fail:
	close_files();
	return 1;
}

int main(int argc, char** argv) 
{
	
	if (argc < 2) {
		usage();
		return 0;	
	}
	
	parse_args(argc, argv);
	
	if (open_files() > 0) {
		exit(-1);
	}

	dump_main();

	close_files();

	do_print_leaks();

	return 0;
}


