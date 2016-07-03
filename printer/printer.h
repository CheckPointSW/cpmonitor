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

#ifndef PRINTER_H
#define PRINTER_H

#include <core.h>
#include "tprint.h"
#include <unistd.h>
#include <termios.h>

typedef enum {
	USAGE_PRINT_PACKETS 	=	0x0001,
	USAGE_PRINT_BYTES		=	0x0002,
	USAGE_PRINT_PRECENTAGE	=	0x0004,
	USAGE_PRINT_AS_KILOBYTS	=	0x0008,
	USAGE_PRINT_AV_PKT_SIZE	=	0x0010,
	USAGE_PRINT_NAV_MODE	=	0x0020,
	USAGE_PRINT_DUMP_MODE	=	0x0040,
	USAGE_PRINT_UNSUP_PACK  =	0x0080,
	USAGE_PRINT_TOTAL_USAGE	=	0x0100,
	USAGE_PRINT_CONN_TABLE	=	0x0200,
	USAGE_PRINT_HOST_TABLE	=	0x0400,
	USAGE_PRINT_SERV_TABLE	=	0x0800,
	USAGE_PRINT_TCP_TABLE	=	0x1000,
	USAGE_PRINT_IN_OUT		=	0x2000,
	USAGE_PRINT_SYN_CNT		=	0x4000,
} usage_print_flags_t;

typedef enum {
	NICE, CSV
} print_type_e;

/* files handlers */
void file_add_usage_to_ent(usage_t * u, usage_t * total_usage, usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off);
void file_add_bidi_usage_to_ent(bidi_usage_t * u, usage_t * total_usage, usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off, uint32 syn_cnt);
void file_add_bidi_usage_headers(usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off);
void file_add_top_ent_to_graph(summed_data_t * top_ents, top_ents_e type, int from, int to, int N, usage_print_flags_t flags, print_type_e p_type, char * buff, int buff_len, int * off);
void file_add_headers_to_graph(top_ents_e type, usage_print_flags_t flags, print_type_e p_type, char * buff, int buff_len, int * off);
void file_add_ent_five_tuple(hash_key_union_t * key, print_type_e p_type, char* buff, int buff_len, int * off, const char * pre_str);
void sum_data_to_one(summed_data_t * sumed_data, int from, int to, int N, summed_data_t * target, BOOL exclude_first_sec);
int count_lines(const char* buff, int off, int buff_len);
char getch(int TimeOut_sec, int vmin);

void print_tables(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int N, int print_flags);
void print_report();


void print_html_types();
void dump_navigate();

int  printer_init();
void printer_fini();

/* go line up (\e[1A) and erase it (\e[K) */
#define ERASE_LAST_LINE printf("\e[1A\e[K") 

#endif
