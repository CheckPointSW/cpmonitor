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
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>


/*
 *	The dump structure:
 *	There are 2 types of dump we support, pcap (from tcpdump) and snoof (from fw monitor).
 *	There strutures are different, but they have some in common:
 *	
 *		|-------------|
 *		| file header |
 *		|-------------|
 *		|  entry #1   |
 *		|-- . . . . --|
 *		|  entry #N   |
 *		|_____________|
 *
 *	The pcap header is 'pcap_file_header'
 *	The snoop file header is 'snoop_v2_file_header'
 *
 *	Each entry has a dump header, 'pcap_pkthdr_t' or 'snoop_v2_pkthdr_t'.
 *	Then there is usualy another header which we aren't interested in, like Ethernet header.
 *	Then there is the packet it self: ip header, tcp/udp header, the data ... 
 *	(At snoop format,  there is a padding after the packet for some reason... )
 *	
 */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#define bswap(x)    ((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00))

#define FORMAT_MAC_ADDR_LEN		18	/* 12 digits + 5 colons + null terminator */

static char dump_buff[64*1024] = {0};
static int last_dump_time = 0;
uint64 entry_counter;

/* debug counters */
static uint64 ether_type_counter = 0;
static uint64 ARP_counter = 0;
static uint64 layer_2_counter = 0;
static uint64 non_ip_counter = 0;

int read_dump_header() {
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
				PRINTE("Unknown tcpdump type\n\n\n");
				return (-1);
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
			PRINTE("Unknown dump type\n\n\n");
			return (-1);
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
			PRINTE("Unknown dump type\n\n\n");
			return (-1);
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
					PRINTE("snoop datalink type %d not supported\n\n\n", snoop_hdr->datalink_t);
					return (-1);
			}

			break;
		default:
			PRINTE("Unknown dump type\n\n\n");
			return (-1);
	}

	return 0;
}

struct timeval get_end_time()
{
	struct timeval curr_time = {0};
	curr_time.tv_sec = last_dump_time;
	curr_time.tv_usec = 0;	
	return curr_time;
}

int calc_time_diff(struct timeval* curr, struct timeval* prev)
{
       int time_diff = 0;
       int factor = (cpmonitor_conf.dump_type == nsec) ? 1000000 : 1000;

       time_diff = (((int)curr->tv_sec - (int)prev->tv_sec)*1000 + ((int)curr->tv_usec - (int)prev->tv_usec)/factor);

       return time_diff;
}

void close_file(FILE** file_ptr)
{
	if (*file_ptr) {
		fclose(*file_ptr);
		*file_ptr = NULL;
	}
}

void close_files()
{
	PRINTD("in close_files\n");

	/*close input file */
	close_file(&cpmonitor_conf.dump_file);

	/* close output files */
	close_file(&cpmonitor_conf.report_file);
	close_file(&cpmonitor_conf.graph_file);
	close_file(&cpmonitor_conf.table_conns_file);
	close_file(&cpmonitor_conf.table_hosts_file);
	close_file(&cpmonitor_conf.table_services_file);
	close_file(&cpmonitor_conf.table_total_usage_file);
}

int open_file(const char* file_name_prefix, const char* file_name, const char* file_ext, FILE** file_ptr)
{
	int ret = -1;
	char csv_name[1024] = {0};

	if (file_name == NULL) {
		PRINTE("open_file: bad agument - file name is NULL\n\n\n");
	}
	else {
		if (file_name_prefix == NULL) {
			snprintf(csv_name, sizeof(csv_name), "%s.%s", file_name, file_ext);
		}
		else {
			snprintf(csv_name, sizeof(csv_name), "%s_%s.%s", file_name_prefix, file_name, file_ext);
		}

		*file_ptr = fopen(csv_name, "w");
		if (*file_ptr == NULL) {
			PRINTE("failed to open %s file\n\n\n", file_name);
		}
		else {
			ret = 0;
		}
	}

	return ret;
}

int open_table_file(const char* file_name, FILE** file_ptr)
{
	return open_file(cpmonitor_conf.table_file_prefix_name, file_name, "csv", file_ptr);
}

int open_files()
{
	int ret = 0;

	if ((ret == 0) && cpmonitor_conf.graph_name) {
		if (0 != open_file(NULL, cpmonitor_conf.graph_name, "csv", &cpmonitor_conf.graph_file)) {
			PRINTE("Failed opening the graph file.\n\n\n");
			ret = -1;
		}
	}

	if ((ret == 0) && cpmonitor_conf.table_file_prefix_name) {
		if ((0 != open_table_file("conns", &cpmonitor_conf.table_conns_file))			||
			(0 != open_table_file("hosts", &cpmonitor_conf.table_hosts_file))			||
			(0 != open_table_file("services", &cpmonitor_conf.table_services_file))		||
			(0 != open_table_file("total_usage", &cpmonitor_conf.table_total_usage_file))) {

				PRINTE("Failed opening the tables' files.\n\n\n");
				ret = -1;
		}
	}

	return ret;
}

/* if vlan header exists, the function extracts the vlan id and updates vlan_hdr_len */
void try_parse_vlan_header(short hdr_protocol_type, char * entry, int header_size, int * vlan_hdr_len, short * vlan_id)
{
	if (ntohs(hdr_protocol_type) == ETHERTYPE_VLAN) {
		memcpy(vlan_id, entry + header_size, sizeof(short));
		*vlan_id = ntohs(*vlan_id);
		*vlan_id = *vlan_id & 0x0FFF;

		/* it adds a 32-bit field between the source MAC address and the EtherType/length fields of the original frame
			we need to advance to the actual linux cooked header */
		*vlan_hdr_len = 4;
	}
}

/* inspired by http://stackoverflow.com/questions/427517/finding-an-interface-name-from-an-ip-address
	and http://stackoverflow.com/questions/6762766/mac-address-with-getifaddrs */
void get_interface_list()
{
	char buf[32] = {0};
	struct ifaddrs * ifaptr = NULL;
	struct sockaddr_ll * s = NULL;

	PRINT("======================================\n");
	PRINTD("\n");
	PRINT("Complete interface list of current machine:\n");

	getifaddrs(&addrs);

	for (ifaptr = addrs; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
		if (((ifaptr)->ifa_addr)->sa_family == AF_PACKET) {
			s = (struct sockaddr_ll*)(ifaptr)->ifa_addr;
			sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1], s->sll_addr[2], s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);

			PRINT("interface name: %s, mac address: %s\n", ifaptr->ifa_name, buf);
		}
	}

	freeifaddrs(addrs);
	PRINT("======================================\n");
}

void get_interface_data(char* entry, char* i_o, char* if_desc)
{
	int i = 0;

	*i_o = entry[0];
	for (i = 0 ; i < (INTERFACE_DESCRIPTION_LENGTH - 1) ; i++) {
		if ((entry[2 + i] != ' ') && (entry[2 + i] != ';') && (entry[2 + i] != ',')) {
			if_desc[i] = entry[2 + i];
		}
	}
}

void print_MAC_addr()
{
	ether_header_t * ether_hdr = NULL;
	char* src_mac_addr_no_padding = NULL;
	char src_mac_addr[FORMAT_MAC_ADDR_LEN] = {0};
	int	a = 0, b = 0, c = 0, d = 0, e = 0, f = 0;

	ether_hdr = (ether_header_t *) dump_buff;
	src_mac_addr_no_padding = ether_ntoa((struct ether_addr *)ether_hdr->ether_shost);
	if (src_mac_addr_no_padding != NULL) {
		if (sscanf(src_mac_addr_no_padding, "%x:%x:%x:%x:%x:%x", &a,&b,&c,&d,&e,&f) == 6)	{
			memset(src_mac_addr, 0, sizeof(src_mac_addr));
			/* add zero padding on the left */
			sprintf(src_mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", a,b,c,d,e,f);
			PRINT("MAC addr: %s | ", src_mac_addr);
		}
		else {
			PRINT("MAC addr: %s | ", src_mac_addr_no_padding);
		}
	}
}

void summerize_timeslot_and_inc(struct timeval* curr, int* second_parsed)
{
	int off = 0;
	int expire_index = 0;
	usage_print_flags_t  usage_print_flags = USAGE_PRINT_PACKETS;

	hash_table_inc_timeslot(&cpmonitor_db, curr);
	cpmonitor_db.sum_unsupported_entries += cpmonitor_db.summed_data[(cpmonitor_db.current_expire_index - 1) % HISTORY_N].unsupported_entries;
	memcpy(&summed_data_arr[(cpmonitor_db.current_expire_index - 1)], &cpmonitor_db.summed_data[(cpmonitor_db.current_expire_index - 1) % HISTORY_N], sizeof(*summed_data_arr));

	(*second_parsed)++;
	PRINTF("Parsed %d seconds\n", *second_parsed);

	if (cpmonitor_conf.graph_name) {
		expire_index = cpmonitor_db.current_expire_index;
		file_add_top_ent_to_graph(cpmonitor_db.summed_data, TOP_CONNS, expire_index - 1, expire_index, 10, usage_print_flags, CSV, dump_buff, sizeof(dump_buff), &off);
		fprintf(cpmonitor_conf.graph_file, "%s\n", dump_buff);
	}
}

void print_debug_counters()
{
	PRINT("======================================\n");
	PRINTD("\n");
	print_unsupported_ipproto_counters();
	PRINT("num of ether_type: %llu\n", ether_type_counter);
	PRINT("num of ARP: %llu\n", ARP_counter);
	PRINT("num of layer 2: %llu\n", layer_2_counter);
	PRINT("num of non ip: %llu\n", non_ip_counter);
	PRINT("Total num of enteries: %llu\n", entry_counter);
	PRINT("num of formally dropped entries: %d\n", cpmonitor_db.sum_unsupported_entries);
	PRINT("======================================\n");
}

int read_dump_loop()
{	
	pcap_pkthdr_t		 pcap_hdr;
	snoop_v2_pkthdr_t	 snoop_hdr = {0};
	void *				 dump_entry_hdr_ptr = NULL;
	int 				 dump_entry_hdr_len = 0;
	char * 				 entry = NULL;
	int 				 first_entry = 1;
	int					 check_mode = 1;
	uint64 				 file_size = 0;
	uint64 				 already_parsed = 0;
	off_t 				 curr_file_ptr = ftello(cpmonitor_conf.dump_file);
	struct timeval		 prev_time = {0};
	ether_header_t * 	 ether_hdr = NULL;
	int					 vlan_hdr_len = 0;
	int					 time_diff = 0;
	int					 percent = 1;
	int					 second_parsed = 0;
	struct				 stat st = {0};
	char				 i_o = '-';
	char				 if_desc[INTERFACE_DESCRIPTION_LENGTH + 1] = {0};
	short				 vlan_id = -1;
	fpos_t				 position;

	memset(&pcap_hdr, 0, sizeof(pcap_hdr));
	entry_counter = 0;
	addrs = NULL;

	if (cpmonitor_conf.debug) {
		get_interface_list();
	}

	fseek(cpmonitor_conf.dump_file, curr_file_ptr, SEEK_SET);
	stat(cpmonitor_conf.dump_name, &st);
	file_size  = st.st_size;

	if (cpmonitor_conf.dump_type == snoop) {
		dump_entry_hdr_len = sizeof(snoop_hdr);
		dump_entry_hdr_ptr = (char *)&snoop_hdr;
	}
	else {
		dump_entry_hdr_len = sizeof(pcap_hdr);
		dump_entry_hdr_ptr = (char *)&pcap_hdr;
	}

	PRINTV("Starting read_dump_loop (of size %llu)\n", file_size);
	while (!feof(cpmonitor_conf.dump_file)) {
		if(second_parsed >= DAEMON_HISTORY_N) {
			break;
		}

		/* init interface data + vlan_hdr_len*/
		i_o = '-';
		vlan_id = -1;
		memset(if_desc, 0, sizeof(if_desc));
		vlan_hdr_len = 0;
	
		entry_counter++;
		if (entry_counter % 100000 == 0) {
			PRINTV("%llu entries have been parsed\n", entry_counter);
			PRINTV("%llu bytes already parsed, %llu curr file ptr (in bytes)\n", already_parsed, curr_file_ptr);
		}

		if (ferror(cpmonitor_conf.dump_file)) {
			PRINTE("ferror - while reading the dump '%s' at entry (#%llu)\n", cpmonitor_conf.dump_name, entry_counter);
			break;
		}
		
		/* progress - file size */
		if (cpmonitor_conf.verbose) {
			curr_file_ptr = ftello(cpmonitor_conf.dump_file);
			if (curr_file_ptr < 0) {
				PRINTE("the dump '%s' is corrupted\n\n\n", cpmonitor_conf.dump_name);
				return (-1);
			}
			else if (curr_file_ptr > (file_size)*(percent/10.0)) {
				percent++;
				already_parsed = curr_file_ptr;
				PRINTV("%llu - bytes already parsed, %llu curr file ptr (in bytes)\n", already_parsed, curr_file_ptr);
				PRINTV("Parsed %llu/%llu KB (%0.1f%%) of the dump (hash table keys: %u, entries %llu)\n",
						already_parsed>>10, file_size>>10, 100.0*(double)(already_parsed)/(double)file_size, cpmonitor_db.hash_table.count, entry_counter);
			}
		}
		
		/* read dump entry header */
		if (fread(dump_entry_hdr_ptr, 1, dump_entry_hdr_len, cpmonitor_conf.dump_file) != dump_entry_hdr_len) {
			if (feof(cpmonitor_conf.dump_file)) break;
			PRINTE("fread pkt_hdr - while reading the dump '%s' at entry (#%llu)\n\n\n", cpmonitor_conf.dump_name, entry_counter);
			return (-1);
		}
		
		if (cpmonitor_conf.dump_type == snoop) {
			pcap_hdr.ts.tv_sec = ntohl(snoop_hdr.sec);
			pcap_hdr.ts.tv_usec = ntohl(snoop_hdr.msec) * 1000;	
			pcap_hdr.len = ntohl(snoop_hdr.orig_length); 
			pcap_hdr.caplen = ntohl(snoop_hdr.record_length) - sizeof(snoop_v2_pkthdr_t);
		}
		else if (cpmonitor_conf.dump_type == tcpdump_big) {
			pcap_hdr.ts.tv_sec = bswap(pcap_hdr.ts.tv_sec);
			pcap_hdr.ts.tv_usec = bswap(pcap_hdr.ts.tv_usec * 1000);	
			pcap_hdr.len = bswap(pcap_hdr.len); 
			pcap_hdr.caplen = bswap(pcap_hdr.caplen);
		}
		/* else if (cpmonitor_conf.dump_type == nsec) no need to transform pcap_hdr */
		
		if (first_entry) {
			prev_time = pcap_hdr.ts;
			cpmonitor_db.summed_data[0].time_start = pcap_hdr.ts;
			first_entry = 0;
		}

		/* if (entry size) > (buffer size), skip entry */
		if (pcap_hdr.caplen > sizeof(dump_buff)) {
			PRINT("Warning, entry size (%u) is larger than dump_buff (%u), skipping entry #%llu\n", pcap_hdr.caplen, sizeof(dump_buff), entry_counter);
			
			if (fgetpos(cpmonitor_conf.dump_file, &position) != 0) {
				PRINTE("fgetpos failed\n\n\n");
				return (-1);
			}
			position.__pos += pcap_hdr.caplen;
			if (fsetpos(cpmonitor_conf.dump_file, &position) != 0) {
				PRINTE("fsetpos failed\n\n\n");
				return (-1);
			}
			continue;
		}
			
		if (fread(dump_buff, 1, pcap_hdr.caplen, cpmonitor_conf.dump_file) != pcap_hdr.caplen) {
			if (feof(cpmonitor_conf.dump_file)) break;
			PRINTE("fread entry - while reading the dump '%s' at entry (#%llu)\n\n\n", cpmonitor_conf.dump_name, entry_counter);
			return (-1);
		}
		entry = dump_buff;

		if (check_mode) {
			if (cpmonitor_conf.dump_type == tcpdump_little) {
				if ((entry[0] == 'i') || (entry[0] == 'o')){
					/* pcap file was created with tcpdump -Penni flag */
					cpmonitor_conf.interface_mode = 1;
				}
				else {
					cpmonitor_conf.mac_addr_mode = 1;
				}
			}

			check_mode = 0;

			/* open the output files */
			if (open_files() != 0) {
				return (-1);
			}
		}

		PRINTD("#%ld | ", (long)entry_counter);

		if (cpmonitor_conf.interface_mode) {
			get_interface_data(entry, &i_o, if_desc);
		}
		else if (cpmonitor_conf.mac_addr_mode && cpmonitor_conf.debug) {
			print_MAC_addr();
		}

		if (cpmonitor_conf.dump_type == snoop) { 
			ether_hdr = (ether_header_t *) dump_buff;
			ether_hdr->ether_type = ntohs(ether_hdr->ether_type);
			entry = dump_buff;
			
			if(ether_hdr->ether_type != ETHERTYPE_IP) {		
				/* not supported. don't handle those entries */
				PRINTV("ether_hdr->ether_type %d not supported.\n", ether_hdr->ether_type);
				cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].unsupported_entries++;
				ether_type_counter++;
				continue;
			}	
		} 		
		else if (cpmonitor_conf.dump_type != snoop && cpmonitor_conf.linklen == 16) {
			/* sometimes there are non ip entries */
			/* we will continue to handle only IP and IPV6 (with or without VLAN additional header - 802 1Q) */
			linux_cooked_hdr_t * linux_cooked_hdr = (linux_cooked_hdr_t *) entry;
			if (ntohs(linux_cooked_hdr->protocol_type) == ETH_P_ARP) {
				PRINTD("found an ARP entry (#%llu), not supported\n", entry_counter);
				cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].unsupported_entries++;
				ARP_counter++;
				continue;
			}
			if (ntohs(linux_cooked_hdr->protocol_type) == ETH_P_802_2) {
				PRINTD("found an layer 2 entry (#%llu), not supported\n", entry_counter);
				cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].unsupported_entries++;
				layer_2_counter++;
				continue;
			}

			if (cpmonitor_conf.dump_type == tcpdump_little) {
				try_parse_vlan_header(linux_cooked_hdr->protocol_type, entry, sizeof(linux_cooked_hdr_t), &vlan_hdr_len, &vlan_id);
				/* we advance the entry now because we want to examine the next header in the entry.
					in order to avoid double advancment we reset vlan_hdr_len to zero */
				entry += vlan_hdr_len;
				linux_cooked_hdr = (linux_cooked_hdr_t *)entry;
				vlan_hdr_len = 0;
			}

			if (!(ntohs(linux_cooked_hdr->protocol_type) == ETH_P_IP || ntohs(linux_cooked_hdr->protocol_type) == ETH_P_IPV6)) {
				PRINTD("found a non ip entry of type %x (#%llu)\n", linux_cooked_hdr->protocol_type, entry_counter);
				cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].unsupported_entries++;
				non_ip_counter++;
				continue;
			}
		}
		else if (cpmonitor_conf.dump_type != snoop && cpmonitor_conf.linklen == 14) {
			ether_hdr = (ether_header_t *) dump_buff;
			try_parse_vlan_header(ether_hdr->ether_type, entry, sizeof(ether_header_t), &vlan_hdr_len, &vlan_id);
		}

#ifdef DEEP_DEBUG
		PRINT("pcap_hdr len:%d, caplen:%d\n", pcap_hdr.len, pcap_hdr.caplen);			
		int i=0;
		for (i=0; i < MIN(pcap_hdr.caplen,35) ; i++) {
			if (i==11+20) PRINT("\t");
			PRINT("%i:%x ",i,(u_char)entry[i]);
		}
		PRINT("\n");
#endif		

		entry 			+= cpmonitor_conf.linklen + vlan_hdr_len;
		pcap_hdr.len 	-= cpmonitor_conf.linklen + vlan_hdr_len;
		pcap_hdr.caplen -= cpmonitor_conf.linklen + vlan_hdr_len;

		if (pcap_hdr.len < 0 || pcap_hdr.caplen < 0) {
			PRINTE("Negative length\n\n\n");
			return (-1);
		}

		if (parse_entry(entry, pcap_hdr.len, pcap_hdr.caplen, &pcap_hdr.ts, i_o, if_desc, vlan_id)) {
			/* an error occured */
			return (-1);
		}

		time_diff = calc_time_diff(&(pcap_hdr.ts), &prev_time);

		while ( time_diff > cpmonitor_conf.timestep ) {
			prev_time.tv_usec 	+= cpmonitor_conf.timestep * 1000;
			prev_time.tv_sec 	+= prev_time.tv_usec/(1000*1000);
			prev_time.tv_usec 	%= (1000*1000);	

			summerize_timeslot_and_inc(&prev_time, &second_parsed);
			
			time_diff = calc_time_diff(&(pcap_hdr.ts), &prev_time);
		}
	}

	last_dump_time = pcap_hdr.ts.tv_sec;
	summerize_timeslot_and_inc(&pcap_hdr.ts, &second_parsed);

	if (cpmonitor_conf.debug) {
		print_debug_counters();
	}

	PRINTV("Finished parsing the dump %s\n", cpmonitor_conf.dump_name);
	PRINTV("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	return 0;
}

int dump_main()
{
	int ret = -1;

	PRINTD("Trying to allocate summed_data_arr.\n");
	summed_data_arr = MALLOC(sizeof(*summed_data_arr)*DAEMON_HISTORY_N);
	if (summed_data_arr == NULL) {
		PRINTE("MALLOC failed!\n\n\n");
		goto cleanup;
	}
	PRINTD("Allocation of summed_data_arr succeeded.\n");
	
 	if (cpmonitor_conf.dump_name == NULL) {
		PRINTE("no dump file requested.\n\n\n");
		goto cleanup;
 	}
	cpmonitor_conf.dump_file = fopen(cpmonitor_conf.dump_name, "rb"); /*read binary*/
	if (!cpmonitor_conf.dump_file) {
		PRINTE("failed opening %s (%s)\n\n\n", cpmonitor_conf.dump_name, strerror(errno));
		goto cleanup;
	}	

	if (cpmonitor_conf.graph_file) {
		int off = 0;
		file_add_headers_to_graph(TOP_CONNS, USAGE_PRINT_PACKETS, CSV, dump_buff, sizeof(dump_buff), &off);
		fprintf(cpmonitor_conf.graph_file, "%s", dump_buff);
	}

 	if (printer_init()) {
		goto cleanup;
	}

	if (core_init()) {
		goto cleanup;
	}

	PRINTD("starting parsing of dump file.\n");
	if (read_dump_header()) {
		goto cleanup;
	}

	if (read_dump_loop()) {
		goto cleanup;
	}

	if (cpmonitor_conf.nav) {
		dump_navigate();
	}
	else {
		print_report();
	}

	ret = 0;
	
cleanup:
	core_fini();
	printer_fini();

	if (summed_data_arr) {		
		FREE(summed_data_arr);
	}

	do_print_leaks();

	close_files();

	return ret;
}

