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

#include "dump.h"
#include <errno.h>
#include <sys/stat.h>


/*
 *	The dump structure:
 *	There are 2 types of dump we support, pcap (from tcpdump) and snoof (from fw monitor).
 *	There strutures are different, but they have some in common:
 *	
 *		|-------------|
 *		| file header |
 *		|-------------|
 *		|  packet #1  |
 *		|-- . . . . --|
 *		|  packet #N  |
 *		|_____________|
 *
 *	The pcap header is 'pcap_file_header'
 *	The snoop file header is 'snoop_v2_file_header'
 *
 *	Each packet has a dump header, 'pcap_pkthdr_t' or 'snoop_v2_pkthdr_t'.
 *	Then there is usualy another header which we aren't interested in, like Ethernet header.
 *	Then there is the packet it self: ip header, tcp/udp header, the data ... 
 *	(At snoop format,  there is a padding after the packet for some reason... )
 *	
 */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#define bswap(x)    ((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00))


char dump_buff[64*1024];
int last_dump_time;
uint64 packet_counter;

void read_dump_header() {
	struct pcap_file_header * 		pcap_hdr  =	(struct pcap_file_header * ) 	dump_buff;
	struct snoop_v2_file_header * 	snoop_hdr = (struct snoop_v2_file_header *) dump_buff;
		
	/* we have to check if it a pcap (tcpdump) cpmonitor_conf.dump_file, or a snoop cpmonitor_conf.dump_file (fw monitor)*/
	fread(dump_buff,1,8,cpmonitor_conf.dump_file);
	if ((0 == memcmp(snoop_hdr->snoop_str,"snoop\0\0\0", 8))) {
		cpmonitor_conf.dump_type = snoop;
		PRINTV("dump type = snoop\n");
	} 
	else {
		switch (pcap_hdr->magic) {
			case 0xa1b23c4d:	/* nano second resolution */
				cpmonitor_conf.dump_type = nsec;
				PRINTV("dump type = nsec\n");
				break;
			case 0xA1B2C3D4:	/* tcpdump capture file (little-endian) */
				cpmonitor_conf.dump_type = tcpdump_little;
				PRINTV("dump type = tcpdump (little endian)\n");
				break;
			case 0xD4C3B2A1:	/* tcpdump capture file (big-endian) */
				cpmonitor_conf.dump_type = tcpdump_big;
				PRINTV("dump type = tcpdump (big endian)\n");
				break;
			default:
				PRINTE("Unknown tcpdump type\n");
				exit(-1);	
		}
	}

	/* read the rest of the header */
	switch(cpmonitor_conf.dump_type) {
		case tcpdump_little:
		case tcpdump_big:
		case nsec:
			fread(dump_buff+8 , 1, sizeof(*pcap_hdr) - 8, cpmonitor_conf.dump_file);
			break;
		case snoop:
			fread(dump_buff+8 , 1, sizeof(*snoop_hdr) - 8, cpmonitor_conf.dump_file);
			break;
		default:
			PRINTE("Unknown dump type\n");
			exit(-1);
	}

	/* we are interested in 2 things: the snaplen and the network-layer/cookie header length */
	/* the snaplen: */
	switch(cpmonitor_conf.dump_type) {
		case tcpdump_big:
			pcap_hdr->snaplen = bswap(pcap_hdr->snaplen);
			pcap_hdr->linktype = bswap(pcap_hdr->linktype);
		case tcpdump_little:
		case nsec:
			PRINTV("pcap_hdr->snaplen = %d\n", pcap_hdr->snaplen);
			if (pcap_hdr->snaplen > sizeof(dump_buff)) {
				PRINT("Warning: snaplen:%u >sizeof(dump_buff):%u\n", pcap_hdr->snaplen, sizeof(dump_buff));
			}
			break;
		case snoop:
		{
			uint32 snoop_snaplen = ETHER_MAX_LEN + sizeof(snoop_v2_pkthdr_t);
			PRINTV("snoop_snaplen = %d\n",snoop_snaplen);
		
			if ( snoop_snaplen > sizeof(dump_buff)) {
				PRINT("Warning: snoop_snaplen:%d > sizeof(dump_buff):%u\n)", snoop_snaplen, sizeof(dump_buff));
			}
			break;
		}
		default:
			PRINTE("Unknown dump type\n");
			exit(-1);
	}
	

	/* the network-layer/cookie header length */
	switch(cpmonitor_conf.dump_type) {
		case tcpdump_big:
		case tcpdump_little:
		case nsec:
			switch (pcap_hdr->linktype) {
				case DLT_EN10MB:
					cpmonitor_conf.linklen = 14;
					break;

				case DLT_FDDI:
					cpmonitor_conf.linklen = 13 + 8;	/* fddi_header + llc */
					break;
					
				case DLT_LINUX_SLL:	/* fake header for Linux cooked packet */
					cpmonitor_conf.linklen = 16 ;
					break;
					
				case DLT_NULL:
					cpmonitor_conf.linklen = 0;
					break;		
				default:
					PRINT("the pcap_hdr linktype (%u) is unknown. Hope for the best.\n",pcap_hdr->linktype);
					cpmonitor_conf.linklen = 0;
					break;
			}
			PRINTV("linktype is %u and linklen is %d\n",pcap_hdr->linktype,cpmonitor_conf.linklen);
			break;
		case snoop:
			snoop_hdr->datalink_t=ntohl(snoop_hdr->datalink_t); 
			PRINTV("snoop_hdr->datalink_t = %d\n", snoop_hdr->datalink_t);
			
			switch(snoop_hdr->datalink_t) {
				case SNOOF_ETHERNET: 
					cpmonitor_conf.linklen = sizeof(ether_header_t);
					break;
				default:
					PRINTE("snoop datalink type %d not supported\n", snoop_hdr->datalink_t);
					exit(-1);
			}

			break;
		default:
			PRINTE("Unknown dump type\n");
			exit(-1);
	}
}

struct timeval get_end_time()
{
	struct timeval curr_time;
	curr_time.tv_sec = last_dump_time;
	curr_time.tv_usec = 0;	
	return curr_time;
}


void read_dump_loop() 
{	
	pcap_pkthdr_t		pcap_hdr;
	snoop_v2_pkthdr_t	snoop_hdr;
	void *				dump_packet_hdr_ptr;
	int 				dump_packet_hdr_len;	
	char * 				packet;
	int 				first_packet = 1;
	uint64 				file_size;
	uint64 				already_parsed = 0;
	uint64 				curr_file_ptr = ftell(cpmonitor_conf.dump_file);
	struct timeval		prev_time = {0};
	ether_header_t * 	ether_hdr;
	int vlan_hdr_len;
	int time_diff, off, expire_index;
	usage_print_flags_t usage_print_flags = USAGE_PRINT_PACKETS;
	int percent = 1;
	int second_paresed = 0;
	struct stat st;

	fseek(cpmonitor_conf.dump_file, curr_file_ptr, SEEK_SET);
	stat(cpmonitor_conf.dump_name, &st);
	file_size  = st.st_size;

	if (cpmonitor_conf.dump_type == snoop) {
		dump_packet_hdr_len = sizeof(snoop_hdr);
		dump_packet_hdr_ptr = (char *)&snoop_hdr;
	}
	else {
		dump_packet_hdr_len = sizeof(pcap_hdr);
		dump_packet_hdr_ptr = (char *)&pcap_hdr;
	}

	PRINTV("Starting read_dump_loop (of size %llu)\n", file_size);
	/* for second counter*/
	PRINTF("\n");
	while (!feof(cpmonitor_conf.dump_file)) {
		if(second_paresed >= DAEMON_HISTORY_N) {
			break;
		}
		vlan_hdr_len = 0;
	
		packet_counter++;
		if (packet_counter % 100000 == 0) {
			PRINTV("%llu packets have been parsed\n", packet_counter);
			PRINTV("%llu already parsed, %llu cutt file ptr\n", already_parsed, curr_file_ptr);			
		}

		if (ferror(cpmonitor_conf.dump_file)) {
			PRINTE("ferror - while reading the dump '%s' at packet (#%llu)\n", cpmonitor_conf.dump_name, packet_counter);
			break;
		}
		
		/* progress - file size */
		if (cpmonitor_conf.verbose) {
			curr_file_ptr = ftell(cpmonitor_conf.dump_file);
			if (curr_file_ptr < 0) {
				PRINTE("the dump '%s' is corrupted\n", cpmonitor_conf.dump_name);
			}
			if (curr_file_ptr > (file_size)*(percent/10.0)) {
				percent++;
				already_parsed = curr_file_ptr;
				PRINTV("%llu - already, %llu - curr\n", already_parsed, curr_file_ptr);
				PRINTV("Parsed %llu/%llu KB (%0.1f%%) of the dump (connections: %u, packets %llu)\n", 
					already_parsed>>10, file_size>>10, 100.0*(double)(already_parsed)/(double)file_size, cpmonitor_db.hash_table.count, packet_counter);
			}
		}
		
		/* read dump packet header */
		if (fread(dump_packet_hdr_ptr, 1, dump_packet_hdr_len, cpmonitor_conf.dump_file) != dump_packet_hdr_len) {
			if (feof(cpmonitor_conf.dump_file)) break;
			PRINTE("fread pkt_hdr - while reading the dump '%s' at packet (#%llu)\n", cpmonitor_conf.dump_name, packet_counter);
			exit (-1);
		}
		
		if (cpmonitor_conf.dump_type == snoop) {
			pcap_hdr.ts.tv_sec = ntohl(snoop_hdr.sec);
			pcap_hdr.ts.tv_usec = ntohl(snoop_hdr.msec) * 1000;	
			pcap_hdr.len = ntohl(snoop_hdr.orig_length); 
			pcap_hdr.caplen = ntohl(snoop_hdr.record_length) - sizeof(snoop_v2_pkthdr_t);
		}
		
		if (cpmonitor_conf.dump_type == tcpdump_big) {
			pcap_hdr.ts.tv_sec = bswap(pcap_hdr.ts.tv_sec);
			pcap_hdr.ts.tv_usec = bswap(pcap_hdr.ts.tv_usec * 1000);	
			pcap_hdr.len = bswap(pcap_hdr.len); 
			pcap_hdr.caplen = bswap(pcap_hdr.caplen);
		}

		if (cpmonitor_conf.dump_type == nsec) {
			pcap_hdr.ts.tv_sec = bswap(pcap_hdr.ts.tv_sec);
			pcap_hdr.ts.tv_usec = bswap(pcap_hdr.ts.tv_usec * 1000000);	
			pcap_hdr.len = pcap_hdr.len; 
			pcap_hdr.caplen = pcap_hdr.caplen;
		}
		
		if (first_packet) {
			prev_time = pcap_hdr.ts;
			cpmonitor_db.summed_data[0].time_start = pcap_hdr.ts;
			first_packet = 0;
		}

		/* if (packet size) > (buffer size), skip packet */
		if (pcap_hdr.caplen > sizeof(dump_buff)) {
			PRINT("Warning, packet size is larger than dump_buff, skipping packet #%llu\n", packet_counter);
			fpos_t position;
			if (fgetpos(cpmonitor_conf.dump_file, &position) != 0) {
				PRINTE("fgetpos failed\n");
				exit(-1);
			}
			position.__pos += pcap_hdr.caplen;
			if (fsetpos(cpmonitor_conf.dump_file, &position) != 0) {
				PRINTE("fsetpos failed\n");
				exit(-1);
			}
			continue;
		}
			
		if (fread(dump_buff, 1, pcap_hdr.caplen, cpmonitor_conf.dump_file) != pcap_hdr.caplen) {
			if (feof(cpmonitor_conf.dump_file)) break;
			PRINTE("fread packet - while reading the dump '%s' at packet (#%llu)\n", cpmonitor_conf.dump_name, packet_counter);
			exit (-1);
		}
		packet = dump_buff;
		
		if (cpmonitor_conf.dump_type == snoop) { 
			ether_hdr = (ether_header_t *) dump_buff;
			ether_hdr->ether_type = ntohs(ether_hdr->ether_type);
			packet = dump_buff;
			
			if(ether_hdr->ether_type != ETHERTYPE_IP) {		
				/* not suppoerted. don't handle those packet */
				PRINTV("ether_hdr->ether_type %d not supported.\n", ether_hdr->ether_type);							
				continue;
			}	
		} 		
		else if (cpmonitor_conf.dump_type != snoop && cpmonitor_conf.linklen == 16) {
			/* sometimes there are non ip packets */
			linux_cooked_hdr_t * linux_cooked_hdr = (linux_cooked_hdr_t *) packet;
			if (ntohs(linux_cooked_hdr->protocol_type) == ETH_P_ARP) {
				PRINTV("found an ARP packet (#%llu), not supported\n", packet_counter);
				continue;
			}
			if (ntohs(linux_cooked_hdr->protocol_type) == ETH_P_802_2) {
				PRINTV("found an layer 2 packet (#%llu), not supported\n", packet_counter);
				continue;
			}
			if (!(ntohs(linux_cooked_hdr->protocol_type) == ETH_P_IP || ntohs(linux_cooked_hdr->protocol_type) == ETH_P_IPV6)) {
				PRINTV("found a non ip packet of type %x (#%llu)\n", linux_cooked_hdr->protocol_type, packet_counter);
				continue;
			}
		}
		else if (cpmonitor_conf.dump_type != snoop && cpmonitor_conf.linklen == 14) {
			ether_hdr = (ether_header_t *) dump_buff;
			ether_hdr->ether_type = ntohs(ether_hdr->ether_type);
			if(ether_hdr->ether_type == (short)ETHERTYPE_VLAN) {		
				vlan_hdr_len = 4;
			}				
		}


#ifdef DEEP_DEBUG
		PRINT("pcap_hdr len:%d, caplen:%d\n", pcap_hdr.len, pcap_hdr.caplen);			
		int i=0;
		for (i=0; i < MIN(pcap_hdr.caplen,35) ; i++) {
			if (i==11+20) PRINT("\t");
			PRINT("%i:%x ",i,(u_char)packet[i]);
		}
		PRINT("\n");
#endif		

		packet 			+= cpmonitor_conf.linklen + vlan_hdr_len;
		pcap_hdr.len 	-= cpmonitor_conf.linklen + vlan_hdr_len;
		pcap_hdr.caplen -= cpmonitor_conf.linklen + vlan_hdr_len;

		if (pcap_hdr.len < 0 || pcap_hdr.caplen < 0) {
			PRINTE("Negative length\n");
			exit(-1);
		}
	
 		parse_packet(packet, pcap_hdr.len, pcap_hdr.caplen);
 		
		time_diff = (((int)pcap_hdr.ts.tv_sec - (int)prev_time.tv_sec)*1000 + ((int)pcap_hdr.ts.tv_usec - (int)prev_time.tv_usec)/1000);

		while ( time_diff > cpmonitor_conf.timestep ) {

			prev_time.tv_usec 	+= cpmonitor_conf.timestep * 1000;	
			prev_time.tv_sec 	+= prev_time.tv_usec/(1000*1000);
			prev_time.tv_usec 	%= (1000*1000);	

			hash_table_inc_timeslot(&cpmonitor_db, &prev_time);
			memcpy(&summed_data_arr[(cpmonitor_db.current_expire_index - 1)], &cpmonitor_db.summed_data[(cpmonitor_db.current_expire_index - 1) % HISTORY_N], sizeof(*summed_data_arr));
			
			curr_file_ptr = ftell(cpmonitor_conf.dump_file);

			ERASE_LAST_LINE;
			second_paresed++;
			PRINTF("Parsed %d seconds\n", second_paresed);
			
			if (cpmonitor_conf.graph_name) {
				off = 0;
				expire_index = cpmonitor_db.current_expire_index;
				file_add_top_ent_to_graph(cpmonitor_db.summed_data, TOP_CONNS, expire_index - 1, expire_index, 10, usage_print_flags, CSV, dump_buff, sizeof(dump_buff), &off);
				fprintf(cpmonitor_conf.graph_file, "%s\n", dump_buff);
	 		}
			
			time_diff = (((int)pcap_hdr.ts.tv_sec - (int)prev_time.tv_sec)*1000 + ((int)pcap_hdr.ts.tv_usec - (int)prev_time.tv_usec)/1000);
		}
		
	}
	
	last_dump_time = pcap_hdr.ts.tv_sec;

	hash_table_inc_timeslot(&cpmonitor_db, &pcap_hdr.ts);
	memcpy(&summed_data_arr[(cpmonitor_db.current_expire_index - 1)], &cpmonitor_db.summed_data[(cpmonitor_db.current_expire_index - 1) % HISTORY_N], sizeof(*summed_data_arr));

	curr_file_ptr = ftell(cpmonitor_conf.dump_file);

	ERASE_LAST_LINE;
	second_paresed++;
	PRINTF("Parsed %d seconds\n", second_paresed);
	
	if (cpmonitor_conf.graph_name) {
		off = 0;
		expire_index = cpmonitor_db.current_expire_index;
		file_add_top_ent_to_graph(cpmonitor_db.summed_data, TOP_CONNS, expire_index - 1, expire_index, 10, usage_print_flags, CSV, dump_buff, sizeof(dump_buff), &off);
		fprintf(cpmonitor_conf.graph_file, "%s\n", dump_buff);
	}

	PRINTV("Finished parsing the dump %s\n", cpmonitor_conf.dump_name);
	PRINTV("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

void dump_main() 
{
	summed_data_arr = MALLOC(sizeof(*summed_data_arr)*DAEMON_HISTORY_N);
	if (summed_data_arr == NULL) {
		PRINTE("MALLOC failed!\n");
		goto fail;
	}
	
 	if (cpmonitor_conf.dump_name == NULL) {
		PRINTE("no dump file requested.\n");
		goto fail;
 	}
	cpmonitor_conf.dump_file = fopen(cpmonitor_conf.dump_name, "rb"); /*read binary*/
	if (!cpmonitor_conf.dump_file) {
		PRINTE("failed opening %s (%s)\n", cpmonitor_conf.dump_name, strerror(errno));
		goto fail;
	}	

	if (cpmonitor_conf.graph_file) {
		int off = 0;
		file_add_headers_to_graph(TOP_CONNS, USAGE_PRINT_PACKETS, CSV, dump_buff, sizeof(dump_buff), &off);
		fprintf(cpmonitor_conf.graph_file, "%s", dump_buff);
	}

 	if (printer_init()) {
		goto fail;
	}

	if (core_init()) {
		goto fail;
	}

	read_dump_header();	
	read_dump_loop();
	if (cpmonitor_conf.nav) {
		dump_navigate();
	}
	else {
		print_report();
	}

	core_fini();
	
	fail:
	printer_fini();
	
	if (cpmonitor_conf.dump_file) {
		fclose(cpmonitor_conf.dump_file);	
	}

	if (summed_data_arr) {		
		FREE(summed_data_arr);
	}
}

