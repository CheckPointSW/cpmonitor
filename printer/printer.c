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

#include "printer.h"
#include "known.h"
#include <time.h>


typedef enum {
	conn_source = 0,
	conn_sport,
	conn_dest,
	conn_dport,
	conn_IPP,
	conn_packets,
	conn_troughput,
	conn_av_size,
	conn_description
} conn_table_t;

typedef enum {
	server_ip = 0,
	server_packets,
	server_troughput,
	server_av_size,
} server_table_t;

typedef enum {
	service_service = 0,
	service_IPP,
	service_packets,
	service_troughput,
	service_av_size,
	service_description
} service_table_t;

typedef struct {
	int from, to;
} range_t;

#define KB (1024ULL)
#define MB (KB * KB)
#define GB (MB * KB)

#define BIT_RES 8
#define BYTE_RES 1

#define DATE_TIME "%D %R:%S"
#define TIME_ONLY "%R:%S"
#define DATE_TIME_LIVE "%D %R:%S\n\n"
#define DATE_TIME_FILE_NAME "%m.%d.%y_%R:%S"
#define DATE_TIME_HISTORY_FILE_NAME "%m.%d.%y_%H%M"

#define LINE_BUFF_LEN 512
#define MAX_SERVICE_DESC_LEN 230


/* inspired by http://stackoverflow.com/questions/7469139/what-is-equivalent-to-getch-getche-in-linux#16361724 */
char getch(int TimeOut_sec, int vmin)
{
    char buf = 0;
    struct termios old = {0};
    if (tcgetattr(0, &old) < 0)
            perror("tcsetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
	/* Minimum number of characters for noncanonical read (MIN). */
    old.c_cc[VMIN] = vmin;
    old.c_cc[VTIME] = 10 * TimeOut_sec;
    if (tcsetattr(0, TCSANOW, &old) < 0)
            perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0)
            perror ("read()");
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(0, TCSADRAIN, &old) < 0)
           perror ("tcsetattr ~ICANON");
    return (buf);
}


static int timeval_to_str(struct timeval * tv, char * buff, int len, int off, char * format, int with_milli)
{
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64];
	nowtime = tv->tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, format, nowtm);
	
	if(with_milli) {
		char milli_sec[12];
		snprintf(milli_sec, 11, "%06ld", tv->tv_usec);
		return snprintf(buff + off, len - off, "%s.%.2s", tmbuf, milli_sec);
	}
	else {
		return snprintf(buff + off, len - off, "%s", tmbuf);
	}
}

static void get_hash_key_fields(hash_key_union_t * key, char * src_ip_buff, uint16 src_buff_size, char * dst_ip_buff, uint16 dst_buff_size, uint16 * dport, uint16 * sport, uint8 * ipproto)
{
	switch (key->key_type) {
		case HASH_IPV6_CONN:
			ipv6_to_str(&key->conn_ipv6.src_ip, src_ip_buff, src_buff_size);
			ipv6_to_str(&key->conn_ipv6.dst_ip, dst_ip_buff, dst_buff_size);
			*dport = key->conn_ipv6.dport;
			*sport = key->conn_ipv6.sport;
			*ipproto = key->conn_ipv6.ipproto;
			break;

		case HASH_IPV4_CONN:
			ipv4_to_str(key->conn_ipv4.src_ip, src_ip_buff, src_buff_size);
			ipv4_to_str(key->conn_ipv4.dst_ip, dst_ip_buff, dst_buff_size);
			*dport = key->conn_ipv4.dport;
			*sport = key->conn_ipv4.sport;
			*ipproto = key->conn_ipv4.ipproto;
			break;

		case HASH_IPV6_SERVER:
			ipv6_to_str(&key->ipv6, src_ip_buff, src_buff_size);
			break;

		case HASH_IPV4_SERVER:
			ipv4_to_str(key->ipv4, src_ip_buff, src_buff_size);
			break;

		case HASH_SERVICE:
			*ipproto = key->service.ipproto;
			break;

		case HASH_NONE:
		case HASH_KEY_MAX:
		default:
			break;
	}
}

static const char * PCKTS_FORMATS[] = { "%8u\t" 	, "%u," };
static const char * BYTES_FORMATS[] = { "%8llu\t" 	, "%llu," };
static const char * PRCNT_FORMATS[] = { "%3d%%\t" 	, "%3d%%," };
#define  P(_str_arr, ...) *off += snprintf(buff + *off, buff_len - *off, _str_arr[p_type], ##__VA_ARGS__)
void file_add_usage_to_ent(usage_t * u, usage_t * total_usage, usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off) 
{
	if(flags & USAGE_PRINT_PRECENTAGE && (total_usage == NULL || total_usage->packets==0)) {
		return;
	}
	
	if(flags & USAGE_PRINT_PACKETS) {
		P(PCKTS_FORMATS, u->packets);
		if(flags & USAGE_PRINT_PRECENTAGE) {
			P(PRCNT_FORMATS, (int)(100*u->packets)/total_usage->packets);
		}
	}
	if(flags & USAGE_PRINT_BYTES) {
		if(flags & USAGE_PRINT_AS_KILOBYTS) {
			P(BYTES_FORMATS, u->bytes>>10);
		}
		else {
			P(BYTES_FORMATS, u->bytes);
		}
		if(flags & USAGE_PRINT_PRECENTAGE) {
			P(PRCNT_FORMATS, (uint64)(100*u->bytes)/total_usage->bytes);
		}
	}
	if(flags & USAGE_PRINT_AV_PKT_SIZE) {
		if(u->packets == 0) {
			P(PCKTS_FORMATS, 0);
		}
		else {
			P(PCKTS_FORMATS,u->bytes/u->packets);
		}
	}
}
#undef P

#define P(_str_arr, ...) *off += snprintf(buff + *off, buff_len - *off, _str_arr[p_type], ##__VA_ARGS__)
void file_add_bidi_usage_to_ent(bidi_usage_t * u, usage_t * total_usage, usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off, uint32 syn_cnt) 
{
	if(flags & USAGE_PRINT_PRECENTAGE && (total_usage == NULL || total_usage->packets==0)) {
		return;
	}
	
	if(flags & USAGE_PRINT_PACKETS) {
		P(PCKTS_FORMATS, (u->c2s.packets + u->s2c.packets));
		if(flags & USAGE_PRINT_PRECENTAGE) {
			P(PRCNT_FORMATS, (int)(100*(u->c2s.packets + u->s2c.packets))/total_usage->packets);
		}
		if(flags & USAGE_PRINT_IN_OUT) {
			P(PCKTS_FORMATS, u->c2s.packets);
			if(flags & USAGE_PRINT_PRECENTAGE) {
				P(PRCNT_FORMATS, (int)(100*u->c2s.packets)/(u->c2s.packets + u->s2c.packets));
			}
			P(PCKTS_FORMATS, u->s2c.packets);
			if(flags & USAGE_PRINT_PRECENTAGE) {
				P(PRCNT_FORMATS, (int)(100*u->s2c.packets)/(u->c2s.packets + u->s2c.packets));
			}
		}
	}
	
	if(flags & USAGE_PRINT_BYTES) {
		if(flags & USAGE_PRINT_AS_KILOBYTS) {
			P(BYTES_FORMATS, (bidi_total_bytes(u))>>10);
		}
		else {
			P(BYTES_FORMATS, bidi_total_bytes(u));
		}
		if(flags & USAGE_PRINT_PRECENTAGE) {
			P(PRCNT_FORMATS, (uint64)(bidi_total_bytes(u))/total_usage->bytes);
		}
		if(flags & USAGE_PRINT_IN_OUT) {
			
			if(flags & USAGE_PRINT_AS_KILOBYTS) {
				P(BYTES_FORMATS, u->c2s.bytes>>10);
			}
			else {
				P(BYTES_FORMATS, u->c2s.bytes);
			}
			
			if(flags & USAGE_PRINT_PRECENTAGE) {
				P(PRCNT_FORMATS, (uint64)(100*u->c2s.bytes)/bidi_total_bytes(u));
			}
			
			if(flags & USAGE_PRINT_AS_KILOBYTS) {
				P(BYTES_FORMATS, u->s2c.bytes>>10);
			}
			else {
				P(BYTES_FORMATS, u->s2c.bytes);
			}
			
			if(flags & USAGE_PRINT_PRECENTAGE) {
				P(PRCNT_FORMATS, (uint64)(100*u->s2c.bytes)/bidi_total_bytes(u));
			}
		}
	}
	
	if(flags & USAGE_PRINT_AV_PKT_SIZE) {
		/* C2S*/
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_64]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_128]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_256]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_512]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_768]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_1024]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_1518]);
		P(PCKTS_FORMATS, u->c2s.pkt_length[pkt_len_jumbo]);
		/* S2C */
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_64]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_128]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_256]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_512]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_768]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_1024]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_1518]);
		P(PCKTS_FORMATS, u->s2c.pkt_length[pkt_len_jumbo]);
	}
	
	if(flags & USAGE_PRINT_AV_PKT_SIZE) {
		if((u->c2s.packets + u->s2c.packets) == 0) {
			P(PCKTS_FORMATS, 0);
		}
		else {
			P(PCKTS_FORMATS, bidi_total_bytes(u)/bidi_total_packets(u));
		}
		if(u->c2s.packets == 0) {
			P(PCKTS_FORMATS, 0);
		}
		else {
			P(PCKTS_FORMATS,u->c2s.bytes/u->c2s.packets);
		}
		if(u->s2c.packets == 0) {
			P(PCKTS_FORMATS, 0);
		}
		else {
			P(PCKTS_FORMATS,u->s2c.bytes/u->s2c.packets);
		}
	}
	if(flags & USAGE_PRINT_SYN_CNT) {
		P(PCKTS_FORMATS, syn_cnt);
	}
}
#undef P


#define P(_format) *off += snprintf(buff + *off, buff_len - *off, _format)
void file_add_bidi_usage_headers(usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len, int * off) 
{
	if(flags & USAGE_PRINT_PACKETS) {
		if(p_type == NICE) P(" Packets\t"); else P("Packets,");
		if(flags & USAGE_PRINT_PRECENTAGE) {
			if(p_type == NICE) P("   %%\t"); else P("%% total,");
		}
		if(flags & USAGE_PRINT_IN_OUT) {
			if(p_type == NICE) P(" c2s\t"); else P("c2s,");
			if(flags & USAGE_PRINT_PRECENTAGE) {
				if(p_type == NICE) P("   %%\t"); else P("%%,");
			}
			if(p_type == NICE) P(" s2c\t"); else P("s2c,");
			if(flags & USAGE_PRINT_PRECENTAGE) {
				if(p_type == NICE) P("   %%\t"); else P("%%,");
			}
		}
	}
	
	if(flags & USAGE_PRINT_BYTES) {
		if(flags & USAGE_PRINT_AS_KILOBYTS) {
			if(p_type == NICE) P("      KB\t"); else P("KB,");
		}
		else {
			if(p_type == NICE)  P("   bytes\t"); else P("bytes,");
		}
		if(flags & USAGE_PRINT_PRECENTAGE) {
			if(p_type == NICE) P("   %%\t"); else P("%% total,");
		}
		if(flags & USAGE_PRINT_IN_OUT) {
			if(p_type == NICE) P(" c2s\t"); else P("c2s,");
			if(flags & USAGE_PRINT_PRECENTAGE) {
				if(p_type == NICE) P("   %%\t"); else P("%%,");
			}
			if(p_type == NICE) P(" s2c\t"); else P("s2c,");
			if(flags & USAGE_PRINT_PRECENTAGE) {
				if(p_type == NICE) P("   %%\t"); else P("%%,");
			}
		}
	}
	if(flags & USAGE_PRINT_AV_PKT_SIZE) {
		if(p_type == NICE) {
			P("c2s_len_64\tc2s_len_128\tc2s_len_256\tc2s_len_512\tc2s_len_768\tc2s_len_1024\tc2s_len_1514\tc2s_len_jumbo\t");
			P("s2c_len_64\ts2c_len_128\ts2c_len_256\ts2c_len_512\ts2c_len_768\ts2c_len_1024\ts2c_len_1514\ts2c_len_jumbo\t"); 
		}
		else {
			P(" c2s_len_64, c2s_len_128, c2s_len_256, c2s_len_512, c2s_len_768, c2s_len_1024, c2s_len_1514, c2s_len_jumbo,");
			P(" s2c_len_64, s2c_len_128, s2c_len_256, s2c_len_512, s2c_len_768, s2c_len_1024, s2c_len_1514, s2c_len_jumbo,"); 
		}
	}
	
	if(flags & USAGE_PRINT_AV_PKT_SIZE) {
		if(p_type == NICE) P("Av. size\t"); else P("Av. size,");
		if(flags & USAGE_PRINT_IN_OUT) {
			if(p_type == NICE) P(" c2s\ts2c\t"); else P("c2s,s2c,");
		}
	}
	if(flags & USAGE_PRINT_SYN_CNT) {
		if(p_type == NICE) P(" SYN counter\t"); else P("SYN counter,");
	}
}
#undef P


BOOL get_key_internet_layers_str(hash_key_union_t * key, print_type_e p_type, char* buff, int buff_len, int * off) 
{
	service_t service;
	char delim = (p_type == NICE) ? '\t':',' ;

#ifdef DEBUG
	if(!buff) {
		PRINTE("'buff' is NULL\n");
		return FALSE;
	}
	if(!key) {
		PRINTE("'key' is NULL\n");
		return FALSE;
	}
	if(!off) {
		PRINTE("'off' is NULL\n");
		return FALSE;
	}	
	if(*off<0) {
		PRINTE("*off<0 = %d\n", *off);
		return FALSE;
	}
	if(*off>=buff_len) {
		PRINTE("*off>=buff_len = %d\n", *off);
		return FALSE;
	}
	if(buff_len<0) {
		PRINTE("buff_len<0 = %d\n", buff_len);
		return FALSE;
	}
	if(!HASH_IS_TYPE_VALID(key)) {
		PRINTE("!HASH_IS_TYPE_VALID(key) key_type = %d\n", key->key_type);
		return FALSE;
	}	
#endif
	service.ipproto = 0;
	switch (key->key_type) {
	case HASH_IPV6_CONN:
		service.ipproto = key->conn_ipv6.ipproto;
		service.port = key->conn_ipv6.dport;
		break;
	
	case HASH_IPV4_CONN:
		service.ipproto = key->conn_ipv4.ipproto;
		service.port = key->conn_ipv4.dport;
		break;

	case HASH_SERVICE:
		service = key->service;
		break;

	case HASH_NONE:
	case HASH_IPV6_SERVER:		
	case HASH_IPV4_SERVER:
	case HASH_KEY_MAX:
		return FALSE;
	}

	if(!proto_name[service.ipproto]) {
		return FALSE;
	}
	
	*off += snprintf(buff + *off, buff_len - *off, "%s%c", proto_name[service.ipproto], delim);
	
	switch (service.ipproto) {
	case IPPROTO_ICMP:
	case IPV6PROTO_ICMP:
		if(service.type < KNOWN_ICMP_MAX && icmp_type_name[service.type]) {
			*off += snprintf(buff + *off, buff_len - *off, "%s%c", icmp_type_name[service.type], delim);
			switch (service.type) {
			case 3: /* DEST_UNREACH */
				if(service.code < KNOWN_ICMP_UNREACH_MAX && icmp_unreach_codes_name[service.code]) {
					*off += snprintf(buff + *off, buff_len - *off, "%s%c", icmp_unreach_codes_name[service.code], delim);					
				}
				else {
					*off += snprintf(buff + *off, buff_len - *off, "%d%c", service.code, delim);
				}
				break;
			case 5:	/* REDIRECT" */
				if(service.code < KNOWN_ICMP_REDIRECT_MAX && icmp_redirect_codes_name[service.code]) {
					*off += snprintf(buff + *off, buff_len - *off, "%s%c", icmp_redirect_codes_name[service.code], delim);					
				}
				else {
					*off += snprintf(buff + *off, buff_len - *off, "%d%c",service.code, delim);
				}			
				break;

			case 11: /* TIME_EXCEEDED */
				if(service.code < KNOWN_ICMP_TIME_EXCEEDED_MAX && icmp_time_exceeded_codes_name[service.code]) {
					*off += snprintf(buff + *off, buff_len - *off, "%s%c", icmp_time_exceeded_codes_name[service.code], delim);					
				}
				else {
					*off += snprintf(buff + *off, buff_len - *off, "%d%c", service.code, delim);
				}
				break;
			}
		}
		else {
			*off += snprintf(buff + *off, buff_len - *off, "%d%c%d%c", service.type, delim, service.code, delim);
		}
		break;
		
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if(service.port < KNOWN_PORT_MAX && tcp_udp_service_name[service.port]) {
			*off += snprintf(buff + *off, buff_len - *off, "%s %s%c", tcp_udp_service_name[service.port], tcp_udp_service_description[service.port], delim);	
		}
		else {
			*off += snprintf(buff + *off, buff_len - *off, "%d%c", service.port, delim);	
		}
		break;
		
	default:
		*off += snprintf(buff + *off, buff_len - *off, "%d%c", service.port, delim);	
		break;
	}
	return TRUE;
}

static const char * IP_FORMATS[] = { "%13s\t" 	, "%s," };
static const char * PORT_FORMATS[] = { "%5d\t" 	, "%d," };
static const char * PROTO_FORMATS[] = { "%5d\t" , "%d," };

#define  P(_str_arr, ...) *off += snprintf(buff + *off, buff_len - *off, _str_arr[p_type], ##__VA_ARGS__)
void file_add_ent_five_tuple(hash_key_union_t * key, print_type_e p_type, char* buff, int buff_len, int * off, const char * pre_str)
{
	char 	src_ip_buff[IP_BUFF_SIZE] = {0};
	char 	dst_ip_buff[IP_BUFF_SIZE] = {0};
	uint16 	dport = 0;
	uint16  sport = 0;
	uint8	ipproto = 0;
	char 	delim = (p_type == NICE) ? '\t':',' ;

#ifdef DEBUG
	if(!buff) {
		PRINTE("'buff' is NULL\n");
		return;
	}
	if(!key) {
		PRINTE("'key' is NULL\n");
		return;
	}
	if(!off) {
		PRINTE("'off' is NULL\n");
		return;
	}	
	if(*off<0) {
		PRINTE("*off<0 = %d\n", *off);
		return;
	}
	if(*off>=buff_len) {
		PRINT("*off>=buff_len = %d\n", *off);
		return;
	}
	if(buff_len<0) {
		PRINTE("buff_len<0 = %d\n", buff_len);
		return;
	}
	if(!HASH_IS_TYPE_VALID(key)) {
		PRINTE("!HASH_IS_TYPE_VALID(key) key_type = %d\n", key->key_type);
		return;
	}	
#endif

	if(pre_str) {
		*off += snprintf(buff + *off, buff_len - *off, "%s,", pre_str);
	}
	
	get_hash_key_fields(key, src_ip_buff, sizeof(src_ip_buff), dst_ip_buff, sizeof(dst_ip_buff), &dport, &sport, &ipproto);

	switch (key->key_type) {
	case HASH_IPV6_CONN:
	case HASH_IPV4_CONN:
		P(IP_FORMATS, src_ip_buff);
		P(PORT_FORMATS, sport);
		P(IP_FORMATS, dst_ip_buff);
		P(PORT_FORMATS, dport);
		if(get_key_internet_layers_str(key, delim, buff, buff_len, off) == FALSE) {
			P(PROTO_FORMATS, ipproto);		
		}
		break;
		
	case HASH_IPV6_SERVER:		
	case HASH_IPV4_SERVER:	
		P(IP_FORMATS, src_ip_buff);
		break;
		
	case HASH_SERVICE:
		if(ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP) {
			P(PORT_FORMATS, key->service.port);
		}
		else {
			P(PORT_FORMATS, key->service.type);
			P(PORT_FORMATS, key->service.code);
		}
		if(get_key_internet_layers_str(key, delim, buff, buff_len, off) == FALSE) {
			P(PROTO_FORMATS, key->service.ipproto);		
		}		
		break;	

	case HASH_NONE:
	case HASH_KEY_MAX:
		break;
	}
}
#undef P

void file_add_ent_to_tables(hash_entry_base_t * ent, usage_t * total_usage, usage_print_flags_t flags, print_type_e p_type, char* buff, int buff_len) 
{
	hash_key_union_t * 	key;
	bidi_usage_t		bidi_u;
	int 				off;

	if(buff == NULL || !ent) {
		return;
	}

	key = HASH_ENT_TO_KEY(ent);

	bidi_u = ent->overall_usage;

 	if(total_usage->packets == 0) {
		buff[0]= '\0';
		return;
	}

	off = 0;
	file_add_bidi_usage_to_ent(&bidi_u, total_usage, flags, p_type, buff, buff_len, &off, ent->syn_cnt);
	file_add_ent_five_tuple(key, p_type, buff, buff_len - off, &off, NULL);
}

void file_add_headers_to_graph(top_ents_e type, usage_print_flags_t flags, print_type_e p_type, char * buff, int buff_len, int * off)
{
	char delim = (p_type == NICE) ? '\t':',';
	
	switch (type) {
	case TOP_CONNS:
		*off += snprintf(buff + *off, buff_len - *off, "top conns\n");
		break;

	case TOP_SERVERS:
		*off += snprintf(buff + *off, buff_len - *off, "top servers\n");
		break;
		
	case TOP_SERVICES:
		*off += snprintf(buff + *off, buff_len - *off, "top services\n");
		break;
	default:
		break;
	}
	
	file_add_bidi_usage_headers(flags, p_type, buff, buff_len, off);
	
	switch (type) {
	case TOP_CONNS:
		*off += snprintf(buff + *off, buff_len - *off, "       source%csport%c         dest%cdport%cproto\n", delim, delim, delim, delim);
		break;

	case TOP_SERVERS:
		*off += snprintf(buff + *off, buff_len - *off, "           ip%c\n", delim);
		break;
		
	case TOP_SERVICES:
		*off += snprintf(buff + *off, buff_len - *off, "proto%cservice%c\n", delim, delim);
		break;
	default:
		break;
	}	
}

void file_print_hash_table(hash_table_t* table) {
	uint32 hash = 0;
	hash_entry_base_t * ent = NULL;
	char line_buff[LINE_BUFF_LEN + MAX_SERVICE_DESC_LEN] = {0};
	char usage_hdr_buff[LINE_BUFF_LEN] = {0};
	int usage_hdr_buff_off = 0;
	usage_t total_usage = {0};
	usage_print_flags_t usage_print_flags = USAGE_PRINT_SYN_CNT | USAGE_PRINT_BYTES | USAGE_PRINT_PACKETS | USAGE_PRINT_PRECENTAGE | USAGE_PRINT_AV_PKT_SIZE | USAGE_PRINT_IN_OUT;

	get_total_usage(&total_usage);
	
	PRINTF("printing connection table with %u elements to %s_*.csv\n", table->count, cpmonitor_conf.table_file_prefix_name);

	file_add_bidi_usage_headers(usage_print_flags, CSV, usage_hdr_buff, sizeof(usage_hdr_buff), &usage_hdr_buff_off);
	
	/* print connections */
	fprintf(cpmonitor_conf.table_conns_file, "%ssource ip,sport,dest ip,dport,protocol,description\n", usage_hdr_buff);
	for (hash = 0 ; hash < table->capacity ; hash++) {
		ent = table->hash[hash];
		while (ent != NULL) {
			if (HASH_IS_FIVETUPLE(ent)) {
				file_add_ent_to_tables(ent, &total_usage, usage_print_flags, CSV, line_buff, sizeof(line_buff));
				fprintf(cpmonitor_conf.table_conns_file, "%s\n", line_buff);
			}
			ent = ent->hash_next;
		}
	}

	/* print hosts */
	fprintf(cpmonitor_conf.table_hosts_file, "%sip\n", usage_hdr_buff);
	for (hash = 0 ; hash < table->capacity ; hash++) {
		ent = table->hash[hash];
		while (ent != NULL) {
			if (HASH_IS_HOST(ent)) {
				file_add_ent_to_tables(ent, &total_usage, usage_print_flags, CSV,  line_buff, sizeof(line_buff));
				fprintf(cpmonitor_conf.table_hosts_file, "%s\n", line_buff);
			}
			ent = ent->hash_next;
		}
	}
	
	/* print services */
	fprintf(cpmonitor_conf.table_services_file, "%sport,service,description\n", usage_hdr_buff);
	for (hash = 0 ; hash < table->capacity ; hash++) {
		ent = table->hash[hash];
		while (ent != NULL) {
			if (HASH_IS_SERVICE(ent)) {
				file_add_ent_to_tables(ent, &total_usage, usage_print_flags, CSV,  line_buff, sizeof(line_buff));
				fprintf(cpmonitor_conf.table_services_file, "%s\n", line_buff);
			}
			ent = ent->hash_next;
		}
	}	
}

#define  P(format_, ...) *off += snprintf(buff + *off, buff_len - *off, format_, ##__VA_ARGS__)
void file_add_top_ent_to_graph(summed_data_t * summed_data, top_ents_e type, int from, int to, int N, usage_print_flags_t flags, print_type_e p_type, char * buff, int buff_len, int * off)
{
	int i;
	top_ent_t * top_ents_arr;
	usage_t u;
	
#ifdef DEBUG 
	if(!summed_data) {
		PRINTE("!summed_data\n");
		return;
	}
	if(!off) {
		PRINTE("!off\n");
		return;
	}
	if(from >= to) {
		PRINTE("from %d >= to %d\n", from, to);
		return;
	}
#endif

	if(N > TOP_N) {
		N = TOP_N;
	}

	while (from < to) {
		top_ents_arr = summed_data[from % HISTORY_N].top_ents[type];

		for(i = TOP_N-1; i>=TOP_N-N; i--) {
			if((top_ents_arr[i].bidi_usage.c2s.packets + top_ents_arr[i].bidi_usage.s2c.packets) == 0) {
				break;
			}
			u.bytes = bidi_total_bytes(&top_ents_arr[i].bidi_usage);
			u.packets = bidi_total_packets(&top_ents_arr[i].bidi_usage);
			file_add_usage_to_ent(&u, &summed_data[from % HISTORY_N].total_usage, flags, p_type, buff, buff_len, off);
			file_add_ent_five_tuple(&top_ents_arr[i].key, p_type, buff, buff_len, off, NULL);
			P("\n");
		}
		from++;
	}
}
#undef P

#define TABLES_SHOW_BORDER TRUE
#define TABLES_SHOW_HEADER TRUE
#define TABLES_SPACES_LEFT 0
#define TABLES_SPACES_BETWEEN 2

void print_tcp_states_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data) 
{
	TPrint *tp;
	
	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, 0);

	tprint_column_add (tp, "TCP Stat", TPAlign_center, TPAlign_left);
	tprint_column_add (tp, "Count", TPAlign_center, TPAlign_right);

	if (summed_data[0].total_usage.packets == 0) {
		tprint_print(tp);
		tprint_free(tp);
		return;
	}
	
	if(summed_data->tcp_stats.syn) {
		tprint_data_add_str (tp, 0, "SYN");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.syn);
	}
	if(summed_data->tcp_stats.syn_ack) {
		tprint_data_add_str (tp, 0, "SYN|ACK");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.syn_ack);
	}
	if(summed_data->tcp_stats.syn_ack_push) {
		tprint_data_add_str (tp, 0, "SYN|ACK|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.syn_ack_push);
	}
	if(summed_data->tcp_stats.syn_push) {
		tprint_data_add_str (tp, 0, "SYN|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.syn_push);
	}
	if(summed_data->tcp_stats.ack) {
		tprint_data_add_str (tp, 0, "ACK");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.ack);
	}
	if(summed_data->tcp_stats.ack_push) {
		tprint_data_add_str (tp, 0, "ACK|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.ack_push);
	}
	if(summed_data->tcp_stats.ack_urg_push) {
		tprint_data_add_str (tp, 0, "ACK|URG|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.ack_urg_push);
	}
	if(summed_data->tcp_stats.ack_urg) {
		tprint_data_add_str (tp, 0, "ACK|URG");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.ack_urg);
	}
	if(summed_data->tcp_stats.fin_ack) {
		tprint_data_add_str (tp, 0, "FIN|ACK");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.fin_ack);
	}
	if(summed_data->tcp_stats.fin_ack_push) {
		tprint_data_add_str (tp, 0, "FIN|ACK|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.fin_ack_push);
	}
	if(summed_data->tcp_stats.fin_ack_urg) {
		tprint_data_add_str (tp, 0, "FIN|ACK|URG");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.fin_ack_urg);
	}
	if(summed_data->tcp_stats.fin_ack_urg_push) {
		tprint_data_add_str (tp, 0, "FIN|ACK|URG|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.fin_ack_urg_push);
	}
	if(summed_data->tcp_stats.rst) {
		tprint_data_add_str (tp, 0, "RST");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.rst);
	}
	if(summed_data->tcp_stats.rst_ack) {
		tprint_data_add_str (tp, 0, "RST|ACK");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.rst_ack);
	}
	if(summed_data->tcp_stats.rst_ack_push) {
		tprint_data_add_str (tp, 0, "RST|ACK|PUSH");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.rst_ack_push);
	}
	if(summed_data->tcp_stats.invalid) {
		tprint_data_add_str (tp, 0, "Invalid");
		tprint_data_add_int32 (tp, 1, summed_data->tcp_stats.invalid);
	}

	tprint_print (tp);
	tprint_free (tp);
}

int count_lines(const char* buff, int off, int buff_len)
{
	int lines = 0;
	const char * char_ptr = buff + off;


#ifdef DEBUG
	if(!buff) {
		PRINTE("'buff' is NULL\n");
		return 0;
	}	
	if(off<0) {
		PRINTE("off<0 = %d\n",off);
		return 0;
	}
	if(off>=buff_len) {
		PRINTE("off %d >= buff_len %d\n", off, buff_len);
		return 0;
	}
	if(buff_len<0) {
		PRINTE("buff_len<0 = %d\n", buff_len);
		return 0;
	}
#endif

	do {
		lines++;
		char_ptr = strchr(char_ptr + 1, '\n');
	} while (char_ptr && (char_ptr < (buff + buff_len)));
	return lines;
}


#define P(_format,...) *off += snprintf(buff + *off, buff_len - *off, _format, ##__VA_ARGS__)
void bytes_convertor_str(uint64 bytes, char* buff, int buff_len, int * off, int b_or_B)
{
	switch(b_or_B) {
		case BYTE_RES:
			if(bytes > 10*GB) {
				P("%llu GB", bytes / GB);
				return;
			}
			if(bytes > 10*MB) {
				P("%llu MB", bytes / MB);
				return;
			}
			if(bytes > 10*KB) {
				P("%llu KB", bytes / KB);
				return;
			}
			P("%llu B", bytes);
			return;
		case BIT_RES:
			if(bytes > (10*GB)/BIT_RES) {
				P("%llu Gb", ((bytes*b_or_B) / GB));
				return;
			}
			if(bytes > (10*MB)/BIT_RES) {
				P("%llu Mb", ((bytes*b_or_B) / MB));
				return;
			}
			if((bytes) > (10*KB)/BIT_RES) {
				P("%llu Kb", ((bytes*b_or_B) / KB));
				return;
			}
			P("%llu b", bytes*b_or_B);
			return;
		default:
			return;
	}
}
#undef P

#define  P_PACK(_buff, ...) snprintf(_buff , sizeof(_buff), "%u (%u%%) [%u%%/%u%%]" , ##__VA_ARGS__)
#define  P_TP(_buff, ...) snprintf(_buff , sizeof(_buff), "%s (%llu%%) [%u%%/%u%%]" , ##__VA_ARGS__)
#define  P_AVG(_buff, ...) snprintf(_buff , sizeof(_buff), "%u/%u" , ##__VA_ARGS__)
#define  P_HEADLINE(_str_arr, ...) *buff_off += snprintf(buffer + *buff_off, buff_len - *buff_off, _str_arr, ##__VA_ARGS__)

void print_top_connection_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int N, int print_flags)
{
	TPrint *tp = NULL;
	int i = 0;
	char src_ip_buff[IP_BUFF_SIZE] = {0};
	char dst_ip_buff[IP_BUFF_SIZE] = {0};
	uint16 	dport = 0;
	uint16  sport = 0;
	uint8	ipproto = 0;
	char usage_str[100] = {0};
	char byte_size[100] = {0};
	char avg_size[100] = {0};
	int flags = USAGE_PRINT_BYTES | USAGE_PRINT_PACKETS | USAGE_PRINT_AV_PKT_SIZE | USAGE_PRINT_PRECENTAGE;
	hash_key_union_t * 	key = NULL;
	top_ent_t * top_ents_arr = NULL;
	int offset = 0;
	int min_rows = 0;

	if (print_flags & USAGE_PRINT_NAV_MODE) {
		min_rows = N;
	}

	P_HEADLINE("Top Connections\n"); 
	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, min_rows);

	tprint_column_add(tp, "source", TPAlign_center, TPAlign_left);
	tprint_column_add(tp, "port", TPAlign_center, TPAlign_right);
    tprint_column_add(tp, "dest", TPAlign_center, TPAlign_left);
	tprint_column_add(tp, "port", TPAlign_center, TPAlign_right);
    tprint_column_add(tp, "ipp", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "packets (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
    tprint_column_add(tp, "size (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "avg", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "desc.", TPAlign_center, TPAlign_left);

	if (summed_data[0].total_usage.packets == 0) {
		tprint_print (tp);
		tprint_free (tp);
		return;
	}

	top_ents_arr = summed_data[0].top_ents[TOP_CONNS];
	
	for(i = TOP_N-1 ; i >= TOP_N-N ; i--) {
		
		key  = &top_ents_arr[i].key;

		/* conn_source + conn_dest + conn_dport + conn_sport + conn_IPP + conn_description */
		get_hash_key_fields(key, src_ip_buff, sizeof(src_ip_buff), dst_ip_buff, sizeof(dst_ip_buff), &dport, &sport, &ipproto);
		switch (key->key_type) {
			case HASH_IPV6_CONN:
				tprint_data_add_str (tp, conn_source, src_ip_buff);
				tprint_data_add_str(tp, conn_dest, dst_ip_buff);
				/* if it's ICMP or ESP do not show ports */
				switch (ipproto) {
					case IPPROTO_ICMP:
					case IPPROTO_ESP:
						tprint_data_add_str(tp, conn_dport, "");	
						tprint_data_add_str(tp, conn_sport, "");
						tprint_data_add_str(tp, conn_description, "");
						break;
					case IPPROTO_SCTP:
						tprint_data_add_int32(tp, conn_dport, dport);
						tprint_data_add_int32(tp, conn_sport, sport);
						tprint_data_add_str(tp, conn_description, "");
						break;
					default:
						tprint_data_add_int32(tp, conn_dport, dport);
						tprint_data_add_int32(tp, conn_sport, sport);

						if(dport < KNOWN_PORT_MAX && tcp_udp_service_name[dport]) {
							tprint_data_add_str(tp, conn_description, tcp_udp_service_name[dport]);
						} 
						else {
							tprint_data_add_str(tp, conn_description, "");
						}
						break;
				}

				if(!proto_name[ipproto]) {
					tprint_data_add_int32(tp, conn_IPP, ipproto);
				} else {
					tprint_data_add_str(tp, conn_IPP, proto_name[ipproto]);
				}
				
				break;
				
			case HASH_IPV4_CONN:
				tprint_data_add_str(tp, conn_source, src_ip_buff);
				tprint_data_add_str (tp, conn_dest, dst_ip_buff);
				/* if it's ICMP or ESP do not show ports */
				switch (key->conn_ipv4.ipproto) {
					case IPPROTO_ICMP:
					case IPPROTO_ESP:
						tprint_data_add_str(tp, conn_dport, "");	
						tprint_data_add_str(tp, conn_sport, "");
						tprint_data_add_str(tp, conn_description, "");
						break;
					case IPPROTO_SCTP:
						tprint_data_add_int32(tp, conn_dport, dport);
						tprint_data_add_int32(tp, conn_sport, sport);
						tprint_data_add_str(tp, conn_description, "");
						break;
					default:
						tprint_data_add_int32(tp, conn_dport, dport);
						tprint_data_add_int32(tp, conn_sport, sport);

						if(dport < KNOWN_PORT_MAX && tcp_udp_service_name[dport]) {
							tprint_data_add_str(tp, conn_description, tcp_udp_service_name[dport]);
						} 
						else {
							tprint_data_add_str(tp, conn_description, "");
						}
						break;
				}

				if(!proto_name[ipproto]) {
					tprint_data_add_int32(tp, conn_IPP, ipproto);
				} else {
					tprint_data_add_str(tp, conn_IPP, proto_name[ipproto]);
				}
				
				break;
			case HASH_NONE:
				goto end;
			default:
				continue;	
		}
		
		/* conn_packets */
		if(flags & USAGE_PRINT_PACKETS) {
			uint32 u_packets;
			uint32 percentage_c2s_u_packets;
			u_packets = top_ents_arr[i].bidi_usage.c2s.packets + top_ents_arr[i].bidi_usage.s2c.packets;
			percentage_c2s_u_packets = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.packets)/u_packets;
			P_PACK(usage_str, u_packets, (int)(100*u_packets)/summed_data[0].total_usage.packets, percentage_c2s_u_packets, 100 - percentage_c2s_u_packets);
			tprint_data_add_str (tp, conn_packets, usage_str);
		}
		
		/* conn_troughput */
		if(flags & USAGE_PRINT_BYTES) {
			uint64 u_bytes;
			uint32 percentage_c2s_u_bytes;
			u_bytes = bidi_total_bytes(&top_ents_arr[i].bidi_usage);
			percentage_c2s_u_bytes = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.bytes)/u_bytes;
			offset = 0;
			bytes_convertor_str(u_bytes, byte_size, 100, &offset, BYTE_RES);
			P_TP(usage_str, byte_size, (uint64)(100*u_bytes)/summed_data[0].total_usage.bytes, percentage_c2s_u_bytes, 100 - percentage_c2s_u_bytes);
			tprint_data_add_str (tp, conn_troughput, usage_str);
		}

		/* conn_av_size */
		if(flags & USAGE_PRINT_AV_PKT_SIZE) {
			uint32 s2c_avg_size;
			uint32 c2s_avg_size;
			if(top_ents_arr[i].bidi_usage.s2c.packets == 0) {
				s2c_avg_size = 0;
			}
			else {
				s2c_avg_size = (uint32)top_ents_arr[i].bidi_usage.s2c.bytes / top_ents_arr[i].bidi_usage.s2c.packets;
			}
			if(top_ents_arr[i].bidi_usage.c2s.packets == 0) {
				c2s_avg_size = 0;
			}
			else {
				c2s_avg_size = (uint32)top_ents_arr[i].bidi_usage.c2s.bytes / top_ents_arr[i].bidi_usage.c2s.packets;
			}
			P_AVG(avg_size, c2s_avg_size, s2c_avg_size);
			tprint_data_add_str (tp, conn_av_size, avg_size);
		}
	}
end:
	tprint_print (tp);
	tprint_free (tp);
}

void print_top_destinations_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int N, int print_flags)
{
	TPrint *tp = NULL;
	int i = 0;
	char src_ip_buff[IP_BUFF_SIZE] = {0};
	char usage_str[100] = {0};
	char byte_size[100] = {0};
	char avg_size[100] = {0};
	int flags = USAGE_PRINT_BYTES | USAGE_PRINT_PACKETS | USAGE_PRINT_AV_PKT_SIZE | USAGE_PRINT_PRECENTAGE;
	hash_key_union_t * key = NULL;
	top_ent_t * top_ents_arr = NULL;
	int offset = 0;
	int min_rows = 0;
	
	if (print_flags & USAGE_PRINT_NAV_MODE) {
		min_rows = N;
	}

	P_HEADLINE("Top destinations\n"); 
	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, min_rows);

	tprint_column_add (tp, "IP", TPAlign_center, TPAlign_left);
	tprint_column_add (tp, "packets (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
    tprint_column_add (tp, "size (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
	tprint_column_add (tp, "avg", TPAlign_center, TPAlign_right);

	if (summed_data[0].total_usage.packets == 0) {
		tprint_print (tp);
		tprint_free (tp);
		return;
	}

	top_ents_arr = summed_data[0].top_ents[TOP_SERVERS];
	
	for(i = TOP_N-1 ; i >= TOP_N-N ; i--) {
		
		key  = &top_ents_arr[i].key;
		
		/* server_ip*/
		switch (key->key_type) {
			case HASH_IPV6_SERVER:
				ipv6_to_str(&key->ipv6, src_ip_buff, sizeof(src_ip_buff));
				tprint_data_add_str (tp, server_ip, src_ip_buff);
				break;

			case HASH_IPV4_SERVER:	
				ipv4_to_str(key->ipv4, src_ip_buff, sizeof(src_ip_buff));
				tprint_data_add_str (tp, server_ip, src_ip_buff);
				break;
			case HASH_NONE:
				goto end;
			default:
				continue;
		}

		/* server_packets */
		if(flags & USAGE_PRINT_PACKETS) {
			uint32 u_packets;
			uint32 percentage_c2s_u_packets;
			u_packets = top_ents_arr[i].bidi_usage.c2s.packets + top_ents_arr[i].bidi_usage.s2c.packets;
			percentage_c2s_u_packets = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.packets)/u_packets;
			P_PACK(usage_str, u_packets, (int)(100*u_packets)/summed_data[0].total_usage.packets, percentage_c2s_u_packets, 100 - percentage_c2s_u_packets);
			tprint_data_add_str (tp, server_packets, usage_str);
		}
		
		/* server_troughput */
		if(flags & USAGE_PRINT_BYTES) {
			uint64 u_bytes;
			uint32 percentage_c2s_u_bytes;
			u_bytes = bidi_total_bytes(&top_ents_arr[i].bidi_usage);
			percentage_c2s_u_bytes = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.bytes)/u_bytes;
			offset = 0;
			bytes_convertor_str(u_bytes, byte_size, 100, &offset, BYTE_RES);
			P_TP(usage_str, byte_size, (uint64)(100*u_bytes)/summed_data[0].total_usage.bytes, percentage_c2s_u_bytes, 100 - percentage_c2s_u_bytes);
			tprint_data_add_str (tp, server_troughput, usage_str);
		}

		/* server_av_size */
		if(flags & USAGE_PRINT_AV_PKT_SIZE) {
			uint32 s2c_avg_size;
			uint32 c2s_avg_size;
			if(top_ents_arr[i].bidi_usage.s2c.packets == 0) {
				s2c_avg_size = 0;
			}
			else {
				s2c_avg_size = (uint32)top_ents_arr[i].bidi_usage.s2c.bytes / top_ents_arr[i].bidi_usage.s2c.packets;
			}
			if(top_ents_arr[i].bidi_usage.c2s.packets == 0) {
				c2s_avg_size = 0;
			}
			else {
				c2s_avg_size = (uint32)top_ents_arr[i].bidi_usage.c2s.bytes / top_ents_arr[i].bidi_usage.c2s.packets;
			}
			P_AVG(avg_size, c2s_avg_size, s2c_avg_size);
			tprint_data_add_str(tp, server_av_size, avg_size);
		}
	}
end:
	tprint_print (tp);
	tprint_free (tp);
}

void print_top_services_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int N, int print_flags)
{
	TPrint *tp = NULL;
	int i = 0;
	char service_buff[100] = {0};
	char usage_str[100] = {0};
	char byte_size[100] = {0};
	char avg_size[100] = {0};
	int flags = USAGE_PRINT_BYTES | USAGE_PRINT_PACKETS | USAGE_PRINT_AV_PKT_SIZE | USAGE_PRINT_PRECENTAGE;
	hash_key_union_t * key = NULL;
	top_ent_t * top_ents_arr = NULL;
	int offset = 0;
	service_t service;
	int min_rows = 0;

	memset(&service, 0, sizeof(service));

	if (print_flags & USAGE_PRINT_NAV_MODE) {
		min_rows = N;
	}

	P_HEADLINE("Top Services\n"); 
	tp = tprint_create(buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, min_rows);

	tprint_column_add(tp, "service", TPAlign_center, TPAlign_right);
    tprint_column_add(tp, "ipp", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "packets (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
    tprint_column_add(tp, "size (%) [c2s/s2c]", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "avg", TPAlign_center, TPAlign_right);
	tprint_column_add(tp, "desc.", TPAlign_center, TPAlign_left);

	if (summed_data[0].total_usage.packets == 0) {
		tprint_print (tp);
		tprint_free (tp);
		return;
	}

	top_ents_arr = summed_data[0].top_ents[TOP_SERVICES];
	
	for(i = TOP_N-1 ; i >= TOP_N-N ; i--) {
		key  = &top_ents_arr[i].key;
		if(key->key_type == HASH_NONE) {
			break;
		}
		service = key->service;

		/* service_IPP */
		if(!proto_name[key->service.ipproto]) {
			tprint_data_add_int32(tp, service_IPP, key->service.ipproto);
		} else {
			tprint_data_add_str(tp, service_IPP, proto_name[key->service.ipproto]);
		}

		
		switch (service.ipproto) {
			case IPPROTO_ICMP:
			case IPV6PROTO_ICMP:
				/* service_service */
				tprint_data_add_str(tp, service_service, "");
				/* service_description */
				if(service.type < KNOWN_ICMP_MAX && icmp_type_name[service.type]) {
					switch (service.type) {
						case 3: /* DEST_UNREACH */
							if(service.code < KNOWN_ICMP_UNREACH_MAX && icmp_unreach_codes_name[service.code]) {
								snprintf(service_buff, 100, "%s(%s)", icmp_type_name[service.type], icmp_unreach_codes_name[service.code]);					
							}
							else {
								snprintf(service_buff, 100, "%d(%d)", service.type, service.code);
							}
							break;
						case 5:	/* REDIRECT" */
							if(service.code < KNOWN_ICMP_REDIRECT_MAX && icmp_redirect_codes_name[service.code]) {
								snprintf(service_buff, 100, "%s(%s)", icmp_type_name[service.type], icmp_redirect_codes_name[service.code]);					
							}
							else {
								snprintf(service_buff, 100, "%d(%d)", service.type, service.code);
							}			
							break;

						case 11: /* TIME_EXCEEDED */
							if(service.code < KNOWN_ICMP_TIME_EXCEEDED_MAX && icmp_time_exceeded_codes_name[service.code]) {
								snprintf(service_buff, 100, "%s(%s)", icmp_type_name[service.type], icmp_time_exceeded_codes_name[service.code]);					
							}
							else {
								snprintf(service_buff, 100, "%d(%d)", service.type, service.code);
							}
							break;
						default:
							snprintf(service_buff, 100, "%s(%d)", icmp_type_name[service.type], service.code);
							break;
					}
				} else {
					snprintf(service_buff, 100, "%d(%d)", service.type, service.code);
				}
				tprint_data_add_str(tp, service_description, service_buff);
				break;	
				
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				/* service_service */
				tprint_data_add_int32(tp, service_service, key->service.port);
				/* service_description */
				if(service.port < KNOWN_PORT_MAX && tcp_udp_service_name[service.port]) {
					tprint_data_add_str(tp, service_description, tcp_udp_service_name[service.port]);
				}
				else {
					tprint_data_add_str(tp, service_description, "");
				}
				break;
			case IPPROTO_SCTP:
				tprint_data_add_int32(tp, service_service, key->service.port);
				tprint_data_add_str(tp, service_description, "");
				break;
			case IPPROTO_ESP:
				/* service_service */
				tprint_data_add_str(tp, service_service, "");
				/* service_description */
				tprint_data_add_str(tp, service_description, "");
				break;
			default:
				/* service_service */
				tprint_data_add_int32(tp, service_service, key->service.port);
				/* service_description */
				tprint_data_add_int32(tp, service_description, service.port);
				break;
		}
		
		/* service_packets */
		if(flags & USAGE_PRINT_PACKETS) {
			uint32 u_packets;
			uint32 percentage_c2s_u_packets;
			u_packets = top_ents_arr[i].bidi_usage.c2s.packets + top_ents_arr[i].bidi_usage.s2c.packets;
			percentage_c2s_u_packets = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.packets)/u_packets;
			P_PACK(usage_str, u_packets, (int)(100*u_packets)/summed_data[0].total_usage.packets, percentage_c2s_u_packets, 100 - percentage_c2s_u_packets);
			tprint_data_add_str (tp, service_packets, usage_str);
		}
		
		/* service_troughput */
		if(flags & USAGE_PRINT_BYTES) {
			uint64 u_bytes;
			uint32 percentage_c2s_u_bytes;
			u_bytes = bidi_total_bytes(&top_ents_arr[i].bidi_usage);
			percentage_c2s_u_bytes = (uint32)(100*top_ents_arr[i].bidi_usage.c2s.bytes)/u_bytes;
			offset = 0;
			bytes_convertor_str(u_bytes, byte_size, 100, &offset, BYTE_RES);
			P_TP(usage_str, byte_size, (uint64)(100*u_bytes)/summed_data[0].total_usage.bytes, percentage_c2s_u_bytes, 100 - percentage_c2s_u_bytes);
			tprint_data_add_str (tp, service_troughput, usage_str);
		}

		/* service_av_size */
		if(flags & USAGE_PRINT_AV_PKT_SIZE) {
			uint32 s2c_avg_size;
			uint32 c2s_avg_size;
			if(top_ents_arr[i].bidi_usage.s2c.packets == 0) {
				s2c_avg_size = 0;
			}
			else {
				s2c_avg_size = (uint32)(top_ents_arr[i].bidi_usage.s2c.bytes / top_ents_arr[i].bidi_usage.s2c.packets);
			}
			if(top_ents_arr[i].bidi_usage.c2s.packets == 0) {
				c2s_avg_size = 0;
			}
			else {
				c2s_avg_size = (uint32)(top_ents_arr[i].bidi_usage.c2s.bytes / top_ents_arr[i].bidi_usage.c2s.packets);
			}
			P_AVG(avg_size, c2s_avg_size, s2c_avg_size);
			tprint_data_add_str(tp, service_av_size, avg_size);
		}
	}

	tprint_print (tp);
	tprint_free (tp);
}
#undef P_PACK
#undef P_TP
#undef P_AVG
#undef P_HEADLINE

void print_nav_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data)
{
	char 	start[96];
	char	end[96];
	TPrint *tp;
	int win_size;
	
	timeval_to_str(&summed_data->time_start, start, sizeof(start), 0, DATE_TIME, 1);
	timeval_to_str(&summed_data->time_end, end, sizeof(end), 0, DATE_TIME, 1);
	win_size = summed_data->time_end.tv_sec - summed_data->time_start.tv_sec;
	if (win_size < 1) {
		win_size = 1;
	}

	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, 0);

	tprint_column_add (tp, "Start time", TPAlign_center, TPAlign_center);
	tprint_column_add (tp, "End time", TPAlign_center, TPAlign_center);
	tprint_column_add (tp, "Win size", TPAlign_center, TPAlign_center);	
	
	tprint_data_add_str (tp, 0, start);
	tprint_data_add_str (tp, 1, end);	
	tprint_data_add_int32 (tp, 2, win_size);

	tprint_print (tp);
	tprint_free (tp);
}

void print_capture_info_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data)
{
	char 	start[96] = {0};
	char	end[96] = {0};
	char	buff[LINE_BUFF_LEN] = {0};
	TPrint *tp = NULL;
	
	timeval_to_str(&summed_data->time_start, start, sizeof(start), 0, DATE_TIME, 1);
	timeval_to_str(&summed_data->time_end, end, sizeof(end), 0, DATE_TIME, 1);

	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, 0);

	tprint_column_add (tp, "Dump Info", TPAlign_center, TPAlign_left);
	snprintf(buff, 511, "Name: %s", cpmonitor_conf.dump_name);
	tprint_data_add_str (tp, 0, buff);
	snprintf(buff, 511, "Start time: %s", start);
	tprint_data_add_str (tp, 0, buff);
	snprintf(buff, 511, "End   time: %s", end);
	tprint_data_add_str (tp, 0, buff);
	
	tprint_print (tp);
	tprint_free (tp);
}

void get_maximum_usage_from_data(summed_data_t * summed_data, int from, int to, maximum_t * maximum)
{
	int j;

	memset(maximum, 0, sizeof(maximum_t));
	
	for(j = from ; j < to ; j++ ) {
		if(summed_data[j].connections > maximum->connection) {
			maximum->connection= summed_data[j].connections;
			maximum->connection_time = summed_data[j].time_start;
		}

		if(summed_data[j].cps > maximum->cps) {
			maximum->cps = summed_data[j].cps;
			maximum->cps_time = summed_data[j].time_start;
		}

		if(summed_data[j].total_usage.packets > maximum->total_usage.packets) {
			maximum->total_usage.packets = summed_data[j].total_usage.packets;
			maximum->packets_usage_time = summed_data[j].time_start;
		}

		if(summed_data[j].total_usage.bytes > maximum->total_usage.bytes) {
			maximum->total_usage.bytes = summed_data[j].total_usage.bytes;
			maximum->bytes_usage_time = summed_data[j].time_start;
		}
	}
}

void sum_data_to_one(summed_data_t * summed_data, int from, int to, int N, summed_data_t * target, BOOL exclude_first_sec)  
{
	static cpmonitor_db_t	tmp_cpmonitor_db;	
	static maximum_t		maximum;
	top_ent_t * 			top_ents_arr = NULL;
	hash_entry_base_t * 	ent = NULL;
	int 					i = 0, j = 0, top_kind = 0;
	int						total_connections = 0;
	uint32					unsupported_entries = 0;
	int						total_cps = 0;
	char					src_ip_buff[IP_BUFF_SIZE] = {0};
	char					dst_ip_buff[IP_BUFF_SIZE] = {0};
	uint16 					dport = 0;
	uint16					sport = 0;
	uint8					ipproto = 0;
	
	if(N > TOP_N) {
		N = TOP_N;
	}

	memset(&maximum, 0, sizeof(maximum));

	memset(&tmp_cpmonitor_db, 0, sizeof(tmp_cpmonitor_db));
	if(hash_init(&tmp_cpmonitor_db.hash_table, 600)) {
		PRINTE("failed to create tmp_hash_table\n\n\n");
		return;
	}

	for(j = from ; j < to ; j++ ) {
		unsupported_entries += summed_data[j].unsupported_entries;
		if (summed_data[j].total_usage.packets == 0) {
			continue;
		}
		accumulate_usage(&tmp_cpmonitor_db.summed_data[0].total_usage, &summed_data[j].total_usage);
		accumulate_tcp_stats(&tmp_cpmonitor_db.summed_data[0].tcp_stats, &summed_data[j].tcp_stats);
		total_connections += summed_data[j].connections;

		if(summed_data[j].connections > maximum.connection) {
			maximum.connection = summed_data[j].connections;
			maximum.connection_time = summed_data[j].time_start;
		}

		if(!exclude_first_sec || j > from) {
			total_cps += summed_data[j].cps;
			if(summed_data[j].cps > maximum.cps) {
				maximum.cps = summed_data[j].cps;
				maximum.cps_time = summed_data[j].time_start;
			}
		}

		if(summed_data[j].total_usage.packets > maximum.total_usage.packets) {
			maximum.total_usage.packets = summed_data[j].total_usage.packets;
			maximum.packets_usage_time = summed_data[j].time_start;
		}

		if(summed_data[j].total_usage.bytes > maximum.total_usage.bytes) {
			maximum.total_usage.bytes = summed_data[j].total_usage.bytes;
			maximum.bytes_usage_time = summed_data[j].time_start;
		}

		for(top_kind = 0; top_kind < TOP_COUNT; top_kind++) {
			for(i = TOP_N-1 ; i >= TOP_N-N ; i--) {
				top_ents_arr = summed_data[j].top_ents[top_kind];
				
				if((top_ents_arr[i].bidi_usage.c2s.packets + top_ents_arr[i].bidi_usage.s2c.packets) == 0) {
					break;
				}
				ent = hash_ent_get(&tmp_cpmonitor_db, &top_ents_arr[i].key, TRUE);
				if(!ent) {
					if (cpmonitor_conf.debug) {
						get_hash_key_fields(&top_ents_arr[i].key, src_ip_buff, sizeof(src_ip_buff), dst_ip_buff, sizeof(dst_ip_buff), &dport, &sport, &ipproto);
						PRINTD("Failed acquiring entry from the table for the following key: src_ip: %s, dst_ip: %s, dport: %d, sport: %d, ipproto: %d.\n",
								(src_ip_buff == NULL)?"NULL":(src_ip_buff), (dst_ip_buff == NULL)?"NULL":(dst_ip_buff), dport, sport, ipproto);
					}
					continue;
				}

				accumulate_bidi_usage(&ent->bidi_usage_per_sec, &top_ents_arr[i].bidi_usage);	
				hash_ent_put_in_top_ents(&tmp_cpmonitor_db, ent);
			}
		}
	}

	tmp_cpmonitor_db.summed_data[0].connections = total_connections;
	tmp_cpmonitor_db.summed_data[0].cps = total_cps;
	tmp_cpmonitor_db.summed_data[0].unsupported_entries = unsupported_entries;
	tmp_cpmonitor_db.summed_data[0].time_start = summed_data[from].time_start;
	
	hash_table_inc_timeslot(&tmp_cpmonitor_db, &summed_data[to-1].time_end);

	tmp_cpmonitor_db.summed_data[0].time_end = summed_data[to-1].time_end;
	
	*target = tmp_cpmonitor_db.summed_data[0];
	memcpy(&(target->maximum), &maximum, sizeof(maximum));
	hash_free(&tmp_cpmonitor_db.hash_table);
}

void print_total_usage_table(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int print_flags)
{
	TPrint *tp = NULL;
	usage_t total = {0};
	int mili_seconds = 0;
	char buff[128] = {0};
	char usage[128] = {0};
	char time[96] = {0};
	int off = 0;

	tp = tprint_create (buffer, buff_len, buff_off, TABLES_SHOW_BORDER, TABLES_SHOW_HEADER, TABLES_SPACES_LEFT, TABLES_SPACES_BETWEEN, 0);

	tprint_column_add (tp, "Total Usage", TPAlign_center, TPAlign_left);

	mili_seconds = calc_time_diff(&(summed_data->time_end), &(summed_data->time_start));
	mili_seconds = (mili_seconds < 1000) ? 1000 : mili_seconds;
	
	total = summed_data->total_usage;

	/* Run time*/
	if(print_flags & USAGE_PRINT_DUMP_MODE) {
		snprintf(buff, sizeof(buff), "Capture duration:        %d.%d seconds", mili_seconds / 1000, mili_seconds % 1000);
		tprint_data_add_str (tp, 0, buff);
	}
	
	/* Total packets */
	snprintf(buff, sizeof(buff), "Total packets:           %u", total.packets);
	tprint_data_add_str (tp, 0, buff);
	
	/* Total packets size */
	bytes_convertor_str(total.bytes, usage, sizeof(usage), &off, BYTE_RES);
	snprintf(buff, sizeof(buff), "Total packets size:      %s", usage);
	tprint_data_add_str (tp, 0, buff);

	/* Average packets per second */
	snprintf(buff, sizeof(buff), "Avg. PPS:                %.2f [packets/second]", 1000.0 * total.packets/mili_seconds);
	tprint_data_add_str (tp, 0, buff);

	/* maxumun packets per second */
	timeval_to_str(&summed_data->maximum.packets_usage_time, time, sizeof(time), 0, TIME_ONLY, 1);
	snprintf(buff, sizeof(buff), "Max PPS:                 %u [packets/second] at %s", summed_data->maximum.total_usage.packets, time);
	tprint_data_add_str (tp, 0, buff);

	/* Average new connections per second */
	snprintf(buff, sizeof(buff), "Avg. CPS:                %.2f [conns/second]", 1000.0 * summed_data->cps / mili_seconds);
	tprint_data_add_str (tp, 0, buff);

	/* Maximum new connections per second */
	timeval_to_str(&summed_data->maximum.cps_time, time, sizeof(time), 0, TIME_ONLY, 1);
	snprintf(buff, sizeof(buff), "Max CPS:                 %u [conns/second] at %s", summed_data->maximum.cps, time);
	tprint_data_add_str (tp, 0, buff);
	
	/* Average throughput */
	off = 0;
	total.bytes = 1000 * total.bytes/mili_seconds;
	bytes_convertor_str(total.bytes, usage, sizeof(usage), &off, BIT_RES);
	snprintf(buff, sizeof(buff), "Avg. throughput:         %s [bits/second]", usage);
	tprint_data_add_str (tp, 0, buff);

	/* Maximum throughput */
	timeval_to_str(&summed_data->maximum.bytes_usage_time, time, sizeof(time), 0, TIME_ONLY, 1);
	off = 0;
	bytes_convertor_str(summed_data->maximum.total_usage.bytes, usage, sizeof(usage), &off, BIT_RES);
	snprintf(buff, sizeof(buff), "Max throughput:          %s [bits/second] at %s", usage, time);
	tprint_data_add_str (tp, 0, buff);

	/* Average active connection per second (streams) */
	snprintf(buff, sizeof(buff), "Avg. concurrent conns:   %.2f [conns/second]", 1000.0 * summed_data->connections / mili_seconds);
	tprint_data_add_str (tp, 0, buff);

	/* Maximum active connections per second */
	timeval_to_str(&summed_data->maximum.connection_time, time, sizeof(time), 0, TIME_ONLY, 1);
	snprintf(buff, sizeof(buff), "Max concurrent conns:    %u [conns/second] at %s", summed_data->maximum.connection, time);
	tprint_data_add_str (tp, 0, buff);

	/* sort method */
	switch (cpmonitor_conf.sort_method) {
		case sort_method_packets:
			snprintf(buff, sizeof(buff), "Sort method:             packets rate");
			break;
		case sort_method_throughput:
			snprintf(buff, sizeof(buff), "Sort method:             throughput");
			break;
		default:
			snprintf(buff, sizeof(buff), "Sort method:             unknown");
			break;
	}
	tprint_data_add_str (tp, 0, buff);

	/* Unsupported packets */
	snprintf(buff, sizeof(buff), "Unsupported entries:     %u", summed_data->unsupported_entries);
	tprint_data_add_str (tp, 0, buff);

	
	tprint_print (tp);
	tprint_free (tp);
}

void file_print_total_usage_table(FILE *table_total_usage_file, summed_data_t * summed_data)
{
	usage_t total = {0};
	int mili_seconds = 0;

	/* print total usage */
	fprintf(table_total_usage_file, "Duration,Packets,Size,Av. PPS,Max PPS,MPPS Time,Av. CPS,Max CPS,MCPS Time,Av. Thrput,Max Thrput,MThrput Time,Av. ACPS,Max ACPS,MACPS Time,Sort,Unsupported,\n");

	mili_seconds = calc_time_diff(&(summed_data->time_end), &(summed_data->time_start));
	mili_seconds = (mili_seconds < 1000) ? 1000 : mili_seconds;

	total = summed_data->total_usage;

	/* Run time (Duration) */
	fprintf(table_total_usage_file, "%d.%d,", mili_seconds / 1000, mili_seconds % 1000);

	/* Total packets (Packets) */
	fprintf(table_total_usage_file, "%u,", total.packets);

	/* Total packets size (Size) */
	fprintf(table_total_usage_file, "%lld,", (long long)(total.bytes*BYTE_RES));

	/* Average packets per second (Av. PPS) */
	fprintf(table_total_usage_file, "%.2f,", 1000.0 * total.packets/mili_seconds);

	/* maximum packets per second (Max PPS, MPPS Time) */
	fprintf(table_total_usage_file, "%u,", summed_data->maximum.total_usage.packets);
	fprintf(table_total_usage_file, "%ld,", summed_data->maximum.packets_usage_time.tv_sec);

	/* Average new connections per second (Av. CPS) */
	fprintf(table_total_usage_file, "%.2f,", 1000.0 * summed_data->cps / mili_seconds);

	/* Maximum new connections per second (Max CPS, MCPS Time) */
	fprintf(table_total_usage_file, "%u,", summed_data->maximum.cps);
	fprintf(table_total_usage_file, "%ld,", summed_data->maximum.cps_time.tv_sec);

	/* Average throughput (Av. Thrput) */
	total.bytes = 1000 * total.bytes/mili_seconds;
	fprintf(table_total_usage_file, "%lld,", (long long)(total.bytes*BIT_RES));

	/* Maximum throughput (Max Thrput, MThrput Time) */
	fprintf(table_total_usage_file, "%lld,", (long long)(summed_data->maximum.total_usage.bytes*BIT_RES));
	fprintf(table_total_usage_file, "%ld,", summed_data->maximum.bytes_usage_time.tv_sec);

	/* Average active connection per second (streams) (Av. ACPS)*/
	fprintf(table_total_usage_file, "%.2f,", 1000.0 * summed_data->connections / mili_seconds);

	/* Maximum active connections per second (Max ACPS, MACPS Time) */
	fprintf(table_total_usage_file, "%u,", summed_data->maximum.connection);
	fprintf(table_total_usage_file, "%ld,", summed_data->maximum.connection_time.tv_sec);

	/* sort method (Sort) */
	switch (cpmonitor_conf.sort_method) {
		case sort_method_packets:
			fprintf(table_total_usage_file, "packets rate,");
			break;
		case sort_method_throughput:
			fprintf(table_total_usage_file, "throughput,");
			break;
		default:
			fprintf(table_total_usage_file, "unknown,");
			break;
	}

	/* Unsupported unsupported_entries (Unsupported) */
	fprintf(table_total_usage_file, "%u,", summed_data->unsupported_entries);
}

void print_tables(char *buffer, int buff_len, int *buff_off, summed_data_t * summed_data, int N, int print_flags)
{		
	if(print_flags & USAGE_PRINT_NAV_MODE) {
		print_nav_table(buffer, buff_len, buff_off, summed_data);
	}

	if(print_flags & USAGE_PRINT_DUMP_MODE && !(print_flags & USAGE_PRINT_NAV_MODE)) {
		print_capture_info_table(buffer, buff_len, buff_off, summed_data);
	}

	if(print_flags & USAGE_PRINT_TOTAL_USAGE) {
		print_total_usage_table(buffer, buff_len, buff_off, summed_data, print_flags);
	}

	if(print_flags & USAGE_PRINT_CONN_TABLE) {
		print_top_connection_table(buffer, buff_len, buff_off, summed_data, N, print_flags);
	}

	if(print_flags & USAGE_PRINT_HOST_TABLE) {
		print_top_destinations_table(buffer, buff_len, buff_off, summed_data, N, print_flags);
	}

	if(print_flags & USAGE_PRINT_SERV_TABLE) {
		print_top_services_table(buffer, buff_len, buff_off, summed_data, N, print_flags);
	}

	if(print_flags & USAGE_PRINT_TCP_TABLE) {
		print_tcp_states_table(buffer, buff_len, buff_off, summed_data);
	}
	
}


void print_report()
{
	char buff[4096*10] = {0};
	int off = 0;
	int N = 10;
	summed_data_t comp_summed_data;

	memset(&comp_summed_data, 0, sizeof(comp_summed_data));

	sum_data_to_one(summed_data_arr, 0, cpmonitor_db.current_expire_index, N, &comp_summed_data, TRUE);

	print_tables(buff, sizeof(buff), &off, &comp_summed_data, N, USAGE_PRINT_DUMP_MODE | USAGE_PRINT_HOST_TABLE | USAGE_PRINT_SERV_TABLE | USAGE_PRINT_TCP_TABLE | USAGE_PRINT_CONN_TABLE | USAGE_PRINT_TOTAL_USAGE);

	PRINT("%s", buff);
	
	if(cpmonitor_conf.table_conns_file) {
		file_print_hash_table(&(cpmonitor_db.hash_table));
		file_print_total_usage_table(cpmonitor_conf.table_total_usage_file, &comp_summed_data);
	}
}


#define P(_buff, _format, ...) _buff##_off += snprintf(_buff + _buff##_off, sizeof(_buff) - _buff##_off, _format, ##__VA_ARGS__)
void dump_navigate() 
{
	summed_data_t summed_data;
	char buffer[4096 * 10] = {0};
	int buffer_off = 0;	
	int line_count = 0;
	range_t req_indexs = {0};
	int win_size = 0;
	int dump_length_in_sec = 0;
	char input = '\0';
	BOOL keep_running = TRUE;
	int N = 5;
	BOOL help = FALSE;
	BOOL refresh = FALSE;
	BOOL exclude_first_sec = FALSE;
	int print_flags = USAGE_PRINT_NAV_MODE | USAGE_PRINT_TOTAL_USAGE | USAGE_PRINT_CONN_TABLE | USAGE_PRINT_HOST_TABLE | USAGE_PRINT_SERV_TABLE | USAGE_PRINT_DUMP_MODE;

	memset(&summed_data, 0, sizeof(summed_data));

	dump_length_in_sec = cpmonitor_db.current_expire_index;
	win_size = 1;
	req_indexs.from = cpmonitor_db.current_expire_index - win_size;
	if(req_indexs.from < 0) {
		req_indexs.from = 0;
	}
	req_indexs.to = cpmonitor_db.current_expire_index;

	system("clear");
	while(keep_running) { 
		/* clear the screen	*/
		line_count = count_lines(buffer, 0, buffer_off);
		while (line_count--) {
			ERASE_LAST_LINE;
		}
		
		if(!help) {
			buffer_off = 0 ;

			if(req_indexs.from == 0) {
				exclude_first_sec = TRUE;
			}
			sum_data_to_one(summed_data_arr, req_indexs.from, req_indexs.to, N, &summed_data, exclude_first_sec);
			exclude_first_sec = FALSE;

			print_tables(buffer, sizeof(buffer), &buffer_off, &summed_data, N, print_flags);

			P(buffer, "\ntype 'h' for help\n");
			PRINTF("%s", buffer);
			
			refresh = FALSE;
			while(!refresh) {
				refresh = TRUE;
				input = getch(0, 1);
				ERASE_LAST_LINE;
				switch(input) {
					case ',':
					case '<':
						req_indexs.from -= (1+win_size)/2;
						if(req_indexs.from < 0) {
							req_indexs.from = 0;
						}
						req_indexs.to = req_indexs.from + win_size;
						break;
					case '.':
					case '>':
						req_indexs.to += (1+win_size)/2;
						if(req_indexs.to > dump_length_in_sec) {
							req_indexs.to = dump_length_in_sec;
						}
						req_indexs.from = req_indexs.to - win_size;
						break;
					case '=':
					case '+':
						win_size++;
						if(win_size > dump_length_in_sec) {
							win_size = dump_length_in_sec;
							break;
						}
						if(win_size == dump_length_in_sec) {
							req_indexs.from = 0;
							req_indexs.to = dump_length_in_sec;
							break;
						}
						req_indexs.to = req_indexs.from + win_size;
						if(req_indexs.to > dump_length_in_sec) {
							req_indexs.to = dump_length_in_sec;
							req_indexs.from = req_indexs.to - win_size;
						}
						break;
					case '-':
						win_size--;
						if(win_size < 1) { 
							win_size = 1;
							break;
						}
						req_indexs.from = req_indexs.to - win_size;
						if(req_indexs.from < 0) {
							req_indexs.from = 0;
							req_indexs.to = req_indexs.from + win_size;
						}
						break;
					case 'q':
						keep_running = FALSE;
						break;
					case 'h':
						help = TRUE;
						break;
					/* Usage table */
					case 'u':
						print_flags ^= USAGE_PRINT_TOTAL_USAGE;
						break;
					/* Connection table */
					case 'c':
						print_flags ^= USAGE_PRINT_CONN_TABLE;
						break;
					/* Destination Table */
					case 'd':
						print_flags ^= USAGE_PRINT_HOST_TABLE;
						break;
					/* Services table */
					case 's':
						print_flags ^= USAGE_PRINT_SERV_TABLE;
						break;
					/* TCP stats table */
					case 't':
						print_flags ^= USAGE_PRINT_TCP_TABLE;
						break;
					/* Increase top number */
					case 'a':
						if(N < TOP_N) {
							N++;
							break;
						}
						refresh = FALSE;
						break;
					/* Decrease top number */
					case 'z':
						if(N > 1) {
							N--;
							break;
						}
						refresh = FALSE;
						break;
					default:
						refresh = FALSE;
						break;
				}
			}
		}
		else {
			buffer_off = 0;
			P(buffer, 	"cpmonitor navigation help:\n"
								"\t+ or =		increase window size\n"
								"\t- or _		decrease window size\n"
								"\t< or ,		decrease dump cursor\n"
								"\t> or .	 	increase dump cursor\n"
								"\tu		toggle usage table\n" 
								"\tc		toggle connection table\n" 
								"\td		toggle destinations table\n" 
								"\ts		toggle services table\n" 
								"\tt		toggle TCP stats table\n"
								"\ta		add line to tables\n" 
								"\tz		remove line from tables\n" 
								"\tq		quit\n" 
								"\n"
								"\tPress any key to return\n"
								);				
			PRINTF("%s", buffer);
			input = getch(0, 1);
			ERASE_LAST_LINE;
			help = FALSE;
			refresh = TRUE;
		}
	}
}
#undef P


int printer_init() 
{
	return known_init();
}

void printer_fini()
{

}

