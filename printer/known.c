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

#include "known.h"

const char *	tcp_udp_service_name[KNOWN_PORT_MAX];
const char *	tcp_udp_service_description[KNOWN_PORT_MAX];
const char *	icmp_type_name[KNOWN_ICMP_MAX];
const char *	icmp_unreach_codes_name[KNOWN_ICMP_UNREACH_MAX];
const char *	icmp_redirect_codes_name[KNOWN_ICMP_REDIRECT_MAX];
const char *	icmp_time_exceeded_codes_name[KNOWN_ICMP_TIME_EXCEEDED_MAX];
const char *	proto_name[IPPROTO_MAX];
const char *	proto_description[IPPROTO_MAX];


int known_init() 
{
	/* ip protocolos */
#define SOME_MACRO(num, type, str, desc) proto_name[num] = str ;
#include "known_ipproto.h"
#undef SOME_MACRO

#define SOME_MACRO(num, type, str, desc) proto_description[num] = desc ;
#include "known_ipproto.h"
#undef SOME_MACRO

	/* tcp and udp */
#define SOME_MACRO(num, name, desc) tcp_udp_service_name[num] = name;
#include "known_services.h"
#undef SOME_MACRO

#define SOME_MACRO(num, name, desc) tcp_udp_service_description[num] = desc;
#include "known_services.h"
#undef SOME_MACRO

	/* icmp */
#define SOME_MACRO(num, name) icmp_type_name[num] = name;
#include "known_icmp_types.h"
#undef SOME_MACRO

#define SOME_MACRO(num, name) icmp_unreach_codes_name[num] = name;
#include "known_icmp_unreach.h"
#undef SOME_MACRO

#define SOME_MACRO(num, name) icmp_redirect_codes_name[num] = name;
#include "known_icmp_redirect.h"
#undef SOME_MACRO

#define SOME_MACRO(num, name) icmp_time_exceeded_codes_name[num] = name;
#include "known_icmp_time_exceeded.h"
#undef SOME_MACRO

	return 0;
}

