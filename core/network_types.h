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

#ifndef NETWORK_TYPES_H
#define NETWORK_TYPES_H

#include "basic_types.h"

/* known interent headers and enums 
 * internet layer: types and headers of ipv4, ipv6, icmp, icmpv6, ipsec. etc.
 * transport layer: tcp, udp
 * apllication layer: services
 */

typedef	uint32				tcp_seq;
typedef uint32				ipv4_addr_t;

/* link layer */
#ifndef ETH_P_IP /* from if_ether.h */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/

#endif


/* Standard well-defined transport layer protocols.  from in.h */
typedef enum ipproto_s {
#define SOME_MACRO(num, type, str, desc) type = num,
#include "known_ipproto.h"
#undef SOME_MACRO
} ipproto_e;

#define _BIT_FIELDS_LTOH
typedef struct {
#ifdef _BIT_FIELDS_LTOH
    unsigned int ip_hl:4;		/**< header length */
    unsigned int ip_v:4;		/**< version */
#else
    unsigned int ip_v:4;		/**< version */
    unsigned int ip_hl:4;		/**< header length */
#endif
    uint8 ip_tos;			/**< type of service */
    uint16 ip_len;			/**< total length */
    uint16 ip_id;			/**< identification */
    uint16 ip_off;			/**< fragment offset field */
    uint8 ip_ttl;			/**< time to live */
    uint8 ip_p;				/**< protocol */
    uint16 ip_sum;			/**< checksum */
    ipv4_addr_t ip_src;		/**< source and dest address */
    ipv4_addr_t ip_dst;	
} ipv4hdr_t;

typedef struct {
	union {
		uint8	u6_addr8[16];
		uint16	u6_addr16[8];
		uint32	u6_addr32[4];
		uint64	u6_addr64[2];		
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
#define s6_addr64		in6_u.u6_addr64
} ipv6_addr_t;

#define	IP_RF 0x8000			/**< reserved fragment flag */
#define	IP_DF 0x4000			/**< dont fragment flag */
#define	IP_MF 0x2000			/**< more fragments flag */
#define	IP_OFFMASK 0x1fff		/**< mask for fragmenting bits */

typedef struct {
  union {
    struct ip6_hdrctl {
      uint32 ip6_un1_flow;	/* 24 bits of flow-ID */
      uint16 ip6_un1_plen;	/* payload length */
      uint8 ip6_un1_nxt;	/* next header */
      uint8 ip6_un1_hlim;	/* hop limit */
    } ip6_un1;
    struct {
#ifdef _BIT_FIELDS_LTOH
	    unsigned int ip_hl:4;		/**< header length */
	    unsigned int ip_v:4;		/**< version */
#else
	    unsigned int ip_v:4;		/**< version */
	    unsigned int ip_hl:4;		/**< header length */
#endif
    };
  } ip6_ctlun;
  
  ipv6_addr_t ip6_src;	/* source address */
  ipv6_addr_t ip6_dst;	/* destination address */

#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen

} ipv6hdr_t;

typedef struct {
	uint16	source;
	uint16	dest;
	uint16	len;
	uint16	check;
} udphdr_t ;

typedef struct {
	uint32 spi;
	uint32 sequence;
} esphdr_t;

typedef struct {
	uint16	source_port;
	uint16	dest_port;
} sctphdr_t;

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80

typedef struct {
	uint16	th_sport;		/**< source port */
	uint16	th_dport;		/**< destination port */
	tcp_seq	th_seq;			/**< sequence number */
	tcp_seq	th_ack;			/**< acknowledgement number */
#ifdef _BIT_FIELDS_LTOH
    uint8  	th_x2:4,        /**< (unused) */
        	th_off:4;       	/**< data offset */
#else
    uint8  	th_off:4,       /**< data offset */
        	th_x2:4;        	/**< (unused) */
#endif
	uint8	th_flags;
	uint16	th_win;			/**< window */
	uint16	th_sum;			/**< checksum */
	uint16	th_urp;			/**< urgent pointer */
} tcphdr_t;

typedef struct {
	union {
		struct {
			uint8	type;
			uint8	code;
		};
		uint16 port;
	};
	uint16	checksum;
	uint32	data;
	/* we care only about type and code */
} icmphdr_t;

/* helping macros */

#define ntohs_impl(___x) \
	((unsigned short)({unsigned short tmp = ___x;  \
		(((tmp & (unsigned short)0x00ffU) << 8) | \
		((tmp & (unsigned short)0xff00U) >> 8));}))

#ifndef  ntohs
#define  ntohs(___x) ntohs_impl(___x)
#endif

#ifndef  htons
#define  htons(___x) ntohs_impl(___x)
#endif

#ifndef _ntohs
#define _ntohs(___x) ntohs_impl(___x)
#endif

#ifndef _htons
#define _htons(___x) ntohs_impl(___x)
#endif

#define ntohl_impl(___x) \
	((unsigned int)({unsigned int tmp = ___x;  \
		(((tmp & (unsigned int)0x000000ffUL) << 24) | \
		((tmp & (unsigned int)0x0000ff00UL) <<  8) | \
		((tmp & (unsigned int)0x00ff0000UL) >>  8) | \
		((tmp & (unsigned int)0xff000000UL) >> 24));}))

#ifndef  ntohl
#define  ntohl(___x) ntohl_impl(___x)
#endif

#ifndef  htonl
#define  htonl(___x) ntohl_impl(___x)
#endif

#ifndef _ntohl
#define _ntohl(___x) ntohl_impl(___x)
#endif

#ifndef _htonl
#define _htonl(___x) ntohl_impl(___x)
#endif

typedef uint16 ipproto_t;

#endif /*NETWORK_TYPES_H*/

