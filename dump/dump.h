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

#ifndef DUMP_H
#define DUMP_H

#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#include "core.h"
#include "printer.h"

typedef unsigned long long 	__u64;
typedef unsigned int 		__u32;
typedef unsigned short 		__u16;
typedef unsigned char 		__u8;

/* pcap headers: */
struct	arc_linux_header {
	__u8  arc_shost;
	__u8  arc_dhost;
	__u16 arc_offset;
	__u8  arc_type;
	__u8  arc_flag;
	__u16 arc_seqid;
};

#define DLT_NULL 0
#define DLT_EN10MB 1
#define DLT_FDDI 10
#define DLT_LINUX_SLL 113


typedef struct {
   	struct timeval ts;	/* time stamp */
    __u32 caplen;       /* length of portion present */
    __u32 len;          /* length this packet (off wire) */
} pcap_pkthdr_t;

typedef struct {
	__u16 packet_type;
	__u16 arphdr_type;
	__u16 linklayer_addr_len;
	__u16 linklayer_addr[4];
	__u16 protocol_type;
} linux_cooked_hdr_t;

/* 
 *	snoop headers.
 * 	see tools.ietf.org/html/rfc1761
 * 	every thing is in "big-endian" order
 */
struct snoop_v2_file_header {
	char 	snoop_str[8]; /* must say: "snoop\0\0\0" */
	int 	version; /* must be 2 */
	int 	datalink_t; /* we support only ethernet */
};

typedef struct {
	char	ether_dhost[ETHER_ADDR_LEN];
	char	ether_shost[ETHER_ADDR_LEN];
	short	ether_type;
} ether_header_t;

/* data link types */
#define SNOOF_IEEE_802_3              0
#define SNOOF_IEEE_802_4_TOKEN_BUS    1
#define SNOOF_IEEE_802_5_TOKEN_RING   2
#define SNOOF_IEEE_802_6_METRO_NET    3
#define SNOOF_ETHERNET                4
#define SNOOF_HDLC                    5
#define SNOOF_CHARACTER_SYNCHRONOUS   6
#define SNOOF_IBM_CHANNEL_TO_CHANNEL  7
#define SNOOF_FDDI                    8
#define SNOOF_OTHER                   9

/* ethernet types (for now we want only IP) */ 
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */

/*
 *  Before each packet there is this header below.
 *  After every packet there is a pad.
 * 	The 'record_length' includes the pad length.
 */

typedef struct {
	__u32 orig_length; /*the packet length (at network layer) */
	__u32 include_length; /* caplen */
	__u32 record_length; /* packet size + this header length */
	__u32 drops; /*how many packet where dropped since the dump begin time*/
	__u32 sec;
	__u32 msec;
} snoop_v2_pkthdr_t;

struct ifaddrs * addrs; /* for debug prints */

int dump_main();

#endif
