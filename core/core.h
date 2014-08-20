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

#ifndef CORE_H
#define CORE_H

#include <sys/time.h>
#include <stddef.h>
#include "string.h"
#include "stdlib.h"
#include "stdio.h"
#include "basic_types.h"
#include "network_types.h"

void * do_malloc(int sz, const char *file, int line);
void do_free(void * ptr, const char* file, int line);

#define MALLOC(sz) do_malloc(sz, __FILE__, __LINE__)
#define FREE(ptr) do_free(ptr, __FILE__, __LINE__)

#ifdef DEBUG
#define LEAK_DEBUG
#endif

void do_print_leaks(void);


#define HZ 	1000 /* defines the timestep (1000 jiffies is 1 second, I think)*/
#define VERB_STR "Verbose: "
#define PRINTV(...) \
	do { \
		if (cpmonitor_conf.verbose) { PRINT(VERB_STR __VA_ARGS__); } \
	} while (0)
#define PRINTE(...) \
	do { \
		PRINT("Error: %s:%d:%s(): ", __FILE__, __LINE__, __func__);\
        PRINT(__VA_ARGS__); \
	} while (0)
#define FPRINT(_f, ...) fprintf(_f, __VA_ARGS__)
#define PRINT(...) \
	do { \
		if (!cpmonitor_conf.quiet) { printf("%s: ", __func__); \
									 printf(__VA_ARGS__);} \
		if (cpmonitor_conf.report_file) fprintf(cpmonitor_conf.report_file, __VA_ARGS__); \
	}while (0)

#define PRINTF(...) if (!cpmonitor_conf.quiet) printf(__VA_ARGS__);

typedef union {
	ipv4_addr_t ipv4;
	ipv6_addr_t ipv6;
} ip_union_t;


#define IPV4_LEN(ip_hdr)				(ntohs(((ipv4hdr_t *) (ip_hdr))->ip_len))
#define IPV6_LEN(ip_hdr)				(ntohs(((ipv6hdr_t *) (ip_hdr))->ip6_plen))
#define IP_LEN(ip_ver, ip_hdr)			((ip_ver == 4) ?  IPV4_LEN(ip_hdr): IPV6_LEN(ip_hdr))

#define IPV4HDR_LEN(ip_hdr)				(((ipv4hdr_t *)(ip_hdr))->ip_hl << 2)
#define IPV6HDR_LEN(ip_hdr)				(40)
#define IPHDR_LEN(ip_ver, ip_hdr)		((ip_ver == 4) ? IPV4HDR_LEN(ip_hdr) : IPV6HDR_LEN(ip_hdr))

#define IPV4_IS_FRAG(ip_hdr)			(ntohs(((ipv4hdr_t *)(ip_hdr))->ip_off) & (IP_DF - 1))
#define IPV6_IS_FRAG(ip_hdr)			(IPV6_P(ip_hdr) == IPV6PROTO_FRAGMENT)
#define IP_IS_FRAG(ip_ver, ip_hdr)		((ip_ver == 4) ? IPV4_IS_FRAG(ip_hdr) : IPV6_IS_FRAG(ip_hdr))

#define IPV4_P(ip_hdr)					(((ipv4hdr_t *)(ip_hdr))->ip_p)
#define IPV6_P(ip_hdr)					(((ipv6hdr_t *)(ip_hdr))->ip6_nxt)
#define IP_P(ip_ver, ip_hdr)			((ip_ver == 4) ? IPV4_P(ip_hdr) : IPV6_P(ip_hdr))

#define IP_VER(ip_hdr)					(((ipv4hdr_t *)(ip_hdr))->ip_v) /*this macro works for IPv4 and 6 (!)*/

#define NXT_HDR_OFF(ip_ver, ip_hdr) 	((uint8*)ip_hdr + IPHDR_LEN(ip_ver, ip_hdr))

#define IPV4_SRC(ip_hdr)				(ntohl(((ipv4hdr_t *)(ip_hdr))->ip_src))
#define IPV4_DST(ip_hdr)				(ntohl(((ipv4hdr_t *)(ip_hdr))->ip_dst))
#define IPV6_SRC(ip_hdr)				(((ipv6hdr_t *)(ip_hdr))->ip6_src)
#define IPV6_DST(ip_hdr)				(((ipv6hdr_t *)(ip_hdr))->ip6_dst)
/* ipv6 doesn't need ntohl, for some reason, see IP_NTOHL at fwip.h */
#define IP_SRC(ip_ver, ip_hdr)			((ip_ver == 4)) ? IPV4_SRC(ip_hdr) : IPV6_SRC(ip_hdr))
#define IP_DST(ip_ver, ip_hdr)			((ip_ver == 4)) ? IPV4_DST(ip_hdr) : IPV6_DST(ip_hdr))

#define TCPHDR_LEN(tcp_hdr)				(tcp_hdr->th_off>>2)
#define TCPDATA(tcp_hdr)				((char*) (tcp_hdr + TCPHDR_LEN(tcp_hdr)))



/* our structs */

/* table of valid flag combinations - from nf_conntrack_proto_tcp.c (only added FIN_ACK */
typedef struct {
	uint32 syn, syn_ack, syn_push, syn_ack_push;
	uint32 rst, rst_ack, rst_ack_push;
	uint32 fin_ack;
	uint32 ack, ack_push, ack_urg, ack_urg_push;
	uint32 fin_ack_push, fin_ack_urg, fin_ack_urg_push;
	uint32 invalid;	
} tcp_stats_t;



enum pkt_len_e{
	pkt_len_64,
	pkt_len_128,
	pkt_len_256,
	pkt_len_512,
	pkt_len_768,
	pkt_len_1024,	
	pkt_len_1518,
	pkt_len_jumbo,
	pkt_len_num_elems
};


typedef struct {
	uint64  bytes;
	uint32  packets;
	uint32	pkt_length[pkt_len_num_elems];	
} usage_t;

typedef struct {
	usage_t s2c;
	usage_t c2s;
} bidi_usage_t;

#define USAGE_CLEAR(_usage) _usage.packets = _usage.bytes = 0
#define BIDI_USAGE_CLEAR(_bidi_usage) _bidi_usage.s2c.packets = _bidi_usage.s2c.bytes = _bidi_usage.c2s.packets = _bidi_usage.c2s.bytes = 0
#define USAGE_CLEAR_PTR(_usage_p) USAGE_CLEAR((*_usage_p))

typedef enum {
	tcpdump_little = 0,
	tcpdump_big = 1,	
	snoop = 2,
	nsec = 3
} dump_type_t;


typedef struct listen_dev_t {
	struct net_device * device;
	struct listen_dev_t *next;
} listen_dev_t;

typedef enum {
	sort_method_packets = 0,
	sort_method_throughput = 1,
	sort_method_unknown =2
} sort_method_t;


typedef int BOOL;
#define TRUE 1
#define FALSE 0

typedef struct {
	uint32 			connection_table_size; 		/* default is 10,000,000 */
	int 			timestep;					/* default is 1 second */
	sort_method_t   sort_method;
	BOOL 			verbose;					/* print some debug messages */
	BOOL 			quiet;						/* no output to stdout, just to the files */
	BOOL			nav;
	int 			linklen;					/* each packets has a linklayer header, we skip it */
	dump_type_t 	dump_type;			
	
	const char * 	dump_name;
	FILE * 			dump_file;
	const char * 	report_name;
	FILE * 			report_file;	
	const char * 	graph_name;
	FILE * 			graph_file;
	const char * 	table_name;
	FILE * 			table_conns_file;
	FILE * 			table_hosts_file;
	FILE * 			table_services_file;
} cpmonitor_conf_t;

typedef struct content_type {
	char* name;
	union {
		struct content_type * next;
		struct content_type * sub_types;
	};
	usage_t u;
} content_type_t;

#define MIN(a,b) ((a)<(b)?(a):(b))

/* multi typed hash */
#define TOP_N 			10
#define HISTORY_N 		60
#define DAEMON_HISTORY_N (60*60*24) 

typedef enum {
	HASH_NONE, /* for empty slots */
	HASH_IPV4_SERVER,
	HASH_IPV4_CONN,
	HASH_IPV6_SERVER,
	HASH_IPV6_CONN,
	HASH_SERVICE,
	/* if you add a type here, don't forget to update hash_key_size*/	 
	HASH_KEY_MAX
} hash_type_t;

typedef enum {
	C2S = 0,
	S2C = 1
} direction_t;


/* this union is created for correct alignment in 64bit machines */
typedef union {
	hash_type_t key_type;
	long dummy;
} hash_type_u;

#define HASH_ENT_TO_KEY(_ent) 	((hash_key_union_t * )(&(_ent)->key_type))
#define HASH_IS_HOST(_a) 		((_a)->key_type==HASH_IPV4_SERVER || (_a)->key_type==HASH_IPV4_SERVER)
#define HASH_IS_FIVETUPLE(_a) 	((_a)->key_type == HASH_IPV4_CONN || (_a)->key_type == HASH_IPV6_CONN )
#define HASH_IS_SERVICE(_a) 	((_a)->key_type == HASH_SERVICE)
#define HASH_IS_TYPE_VALID(_a)	((_a)->key_type == HASH_IPV4_SERVER || (_a)->key_type == HASH_IPV4_CONN || \
								 (_a)->key_type == HASH_IPV6_SERVER || (_a)->key_type == HASH_IPV6_CONN || \
								 (_a)->key_type == HASH_SERVICE )

typedef struct {
	union {
		uint16 	port;
		struct { /* for icmp */
			uint8 type;
			uint8 code;
		};
	};
	ipproto_t ipproto;
} service_t;

typedef struct {
	ipv4_addr_t src_ip;
	ipv4_addr_t dst_ip;	
	union {
		struct {
			uint16 	sport;
			uint16 	dport;	
		};
		uint32 ports;
	};	
	ipproto_t ipproto;
} ipv4_fivetuple_t;

typedef struct {
	ipv6_addr_t src_ip;
	ipv6_addr_t dst_ip;	
	union {
		struct {
			uint16 	sport;
			uint16 	dport;	
		};
		int ports;
	};
	ipproto_t ipproto;
} ipv6_fivetuple_t;

typedef struct {
	hash_type_u key_type_u;
#define key_type key_type_u.key_type

	union {
		ipv4_addr_t ipv4;
		ipv6_addr_t ipv6;
		ipv4_fivetuple_t conn_ipv4;
		ipv6_fivetuple_t conn_ipv6;
		service_t service;
		char data[0];
	};
} hash_key_union_t;

struct hash_entry_base_s; 

typedef struct { /* the order of the members is very important */	
	struct hash_entry_base_s * ent;
	bidi_usage_t bidi_usage;
	hash_key_union_t key;
} top_ent_t;

typedef enum {
	TOP_CONNS,
	TOP_SERVERS,
	TOP_SERVICES,
	TOP_COUNT
} top_ents_e;

typedef struct {
	usage_t			total_usage;
	uint32			connection;
	uint32			cps;
	struct timeval	connection_time;
	struct timeval	cps_time;
	struct timeval	packets_usage_time;
	struct timeval	bytes_usage_time;
} maximum_t;

typedef struct {
	top_ent_t  		top_ents[TOP_COUNT][TOP_N];
	usage_t			total_usage;	
	struct timeval	time_start;
	struct timeval	time_end;	
	int				connections;
	int				cps;
	sort_method_t	sort_method;
	tcp_stats_t 	tcp_stats;
	maximum_t		maximum;
	uint32			unsupported_packets;		
} summed_data_t;

typedef struct hash_entry_base_s {
	int expire_index;	
	struct hash_entry_base_s * expire_prev;
	struct hash_entry_base_s * expire_next;
	struct hash_entry_base_s * hash_next;
	int top_ent_index;  /* -1 means its not in the table */
	bidi_usage_t overall_usage;
	uint32 syn_cnt;
	bidi_usage_t bidi_usage_per_sec;

	/* the last 2 entries must be in this order, and last! */
	hash_type_u key_type_u;
#define key_type key_type_u.key_type
	char data[0];
	/* don't add anything here */
} hash_entry_base_t;

typedef struct {
	hash_entry_base_t ** hash;
	uint32 				size; 	/*the array size*/
	uint32 				count; 	/*the number of elemts currently in*/
	hash_entry_base_t * expire_ring[HISTORY_N]; 
} hash_table_t;


typedef struct {
	usage_t 		total_usage;
	hash_table_t 	hash_table;
	int 			current_expire_index;
	int				num_of_hash_overflows;
	summed_data_t 	summed_data[HISTORY_N];
} cpmonitor_db_t;

extern summed_data_t * summed_data_arr;
extern cpmonitor_db_t cpmonitor_db;
extern cpmonitor_conf_t cpmonitor_conf;

struct  timeval get_end_time();
void 	inc_usage(usage_t * u, int bytes);
int 	hash_init(hash_table_t* table, int size);
void 	hash_free(hash_table_t * table);
hash_entry_base_t * hash_ent_get(cpmonitor_db_t * db, hash_key_union_t * key, BOOL add);
int 	core_init();
void 	core_fini();
void 	parse_packet(void * data, int size, uint32 cap_len);
void hash_table_inc_timeslot(cpmonitor_db_t * db, struct timeval * tv);
void hash_ent_put_in_top_ents(cpmonitor_db_t * db, hash_entry_base_t * ent);
void accumulate_usage(usage_t * to, usage_t * from);
void accumulate_bidi_usage(bidi_usage_t * to, bidi_usage_t * from);
void accumulate_tcp_stats(tcp_stats_t * to, tcp_stats_t * from);
void get_total_usage(usage_t * u);

__inline static uint32 bidi_total_packets(bidi_usage_t * bi_u)
{
	return (bi_u->c2s.packets + bi_u->s2c.packets);
}

__inline static uint64 bidi_total_bytes(bidi_usage_t * bi_u)
{
	return (bi_u->c2s.bytes + bi_u->s2c.bytes);
}

#endif
