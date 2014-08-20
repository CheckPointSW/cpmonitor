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

#ifndef __KNOWN_H__

#define __KNOWN_H__

#define KNOWN_PORT_MAX (49000 + 1)
#define KNOWN_ICMP_MAX 40
#define KNOWN_ICMP_UNREACH_MAX 16
#define KNOWN_ICMP_REDIRECT_MAX 4
#define KNOWN_ICMP_TIME_EXCEEDED_MAX 2
#define IPPROTO_MAX 256

extern const char *	tcp_udp_service_name[KNOWN_PORT_MAX];
extern const char *	tcp_udp_service_description[KNOWN_PORT_MAX];
extern const char *	icmp_type_name[KNOWN_ICMP_MAX];
extern const char *	icmp_unreach_codes_name[KNOWN_ICMP_UNREACH_MAX];
extern const char *	icmp_redirect_codes_name[KNOWN_ICMP_REDIRECT_MAX];
extern const char *	icmp_time_exceeded_codes_name[KNOWN_ICMP_TIME_EXCEEDED_MAX];
extern const char *	proto_name[IPPROTO_MAX];
extern const char *	proto_description[IPPROTO_MAX];

int known_init();

#endif

