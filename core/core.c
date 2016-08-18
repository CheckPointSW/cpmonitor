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
#define LIKELY(cond) 	__builtin_expect((cond),1)
#define UNLIKELY(cond) 	__builtin_expect((cond),0)

summed_data_t *	summed_data_arr;
cpmonitor_db_t 	cpmonitor_db;
BOOL is_report_file_open;

cpmonitor_conf_t cpmonitor_conf = { 
	.timestep = 				HZ,
	.connection_table_size = 	10000000,
};


typedef enum {
	MALLOC_HEADER_TYPE_UNDER_4K = 1,
	MALLOC_HEADER_TYPE_OVER_4K = 2,
} malloc_header_type;

typedef struct {
	uint32				size;
	malloc_header_type 	type;
} malloc_header_t;

#ifdef LEAK_DEBUG
struct allocation_s {
	struct allocation_s *next;
	const char *file;
	int line;
	uint32 size;
	void *ptr;
};
static struct allocation_s all_allocations;
#endif

static uint32 total_allocations = 0;

static uint32 pkt_len[pkt_len_num_elems] = {64,
	128,
	256,
	512,
	768,
	1024,
	1518,
	65535};

/* debug counters */
static int small_IPV4HDR_LEN = 0;
static int IPV4_FRAG_not_IPPROTO_ESP_SCTP = 0;
static int small_IPV6HDR_LEN = 0;
static int IPV6_FRAG_not_IPPROTO_ESP_SCTP = 0;
static int unsupported_ip = 0;
static int small_icmphdr_t = 0;
static int small_tcphdr_t = 0;
static int unknown_tcp_flag = 0;
static int small_udphdr_t = 0;
static int small_esphdr_t = 0;
static int small_sctphdr_t = 0;
static int unsupported_ipproto = 0;

void * do_malloc(uint32 sz, const char * file, int line)
{
#ifdef LEAK_DEBUG
	struct allocation_s *curr = malloc(sizeof(*curr));
#endif

	void * ptr = NULL;
	malloc_header_t hdr;
	short hdr_size = sizeof(hdr);

	memset(&hdr, 0, hdr_size);
	sz += hdr_size;

	ptr = malloc(sz);
	if (LIKELY(ptr != NULL)) {
		hdr.size = sz;

		if (UNLIKELY(sz > 4096)) {
			hdr.type = MALLOC_HEADER_TYPE_OVER_4K;
		}
		else {
			hdr.type = MALLOC_HEADER_TYPE_UNDER_4K;
		}

#ifdef LEAK_DEBUG
		if (curr) {
			curr->file = file;
			curr->line = line;
			curr->size = hdr.size;
			curr->ptr = ptr;
			curr->next = all_allocations.next;
			all_allocations.next = curr;
		}
		else {
			PRINT("failed to add %s:%d to all_allocations\n", file, line);
		}
#endif
		total_allocations += hdr.size;
		memset(ptr, 0, sz);
		memcpy(ptr, &hdr, hdr_size);
		ptr = ((malloc_header_t *)ptr) + 1;
	}

	return ptr;
}

void do_free(void * ptr, const char * file, int line)
{
#ifdef LEAK_DEBUG
	struct allocation_s *curr = NULL;
	struct allocation_s *prev = NULL;
#endif

	malloc_header_t* hdr = NULL;

	if (UNLIKELY(ptr == NULL)) {
		PRINT("NULL free at %s:%d", file, line);
		return;
	}

	hdr = ((malloc_header_t *)ptr) - 1;
	total_allocations -= hdr->size;

	free(hdr);

#ifdef LEAK_DEBUG
	curr = all_allocations.next;
	prev = &all_allocations;
	while (curr) {
		if (curr->ptr == hdr) {
			prev->next = curr->next;
			free(curr);
			goto found;
		}
		else {
			prev = curr;
			curr = curr->next;
		}
	}
	PRINT("failed to remove %s:%d from all_allocations\n", file, line);
found:
	return;
#endif
}


void do_print_leaks(void)
{
#ifdef LEAK_DEBUG
	struct allocation_s *curr = all_allocations.next;

	while(curr) {
		struct allocation_s *next = curr->next;
		PRINT("Leaked %d bytes from %s:%d\n", curr->size, curr->file, curr->line);
		FREE(curr);
		curr = next;
	}
#endif

	if (total_allocations) {
		PRINT("WARNING: %d bytes leaked on close\n", total_allocations);
	}
}

void ipv6_to_str(ipv6_addr_t * addr, char * buf, uint32 len)
{
	int i = 0, off = 0, in_zeros = 0;

	for(i = 0 ; i < 15 ; i++) {
		if(addr->s6_addr[i] == 0) {
			in_zeros = 1;
			continue;
		}
		else {
			if(in_zeros) {
				off += snprintf(buf + off, len - off, ":");
			}
			in_zeros = 0;
		}
		off += snprintf(buf + off, len - off, "%x:", addr->s6_addr[i]);
	}
	if(in_zeros) {
		off += snprintf(buf + off, len - off, ":");
	}
	snprintf(buf + off, len - off, "%x", addr->s6_addr[15]);
}

void ipv4_to_str(ipv4_addr_t addr, char * buf, uint32 len)
{
	snprintf(buf, len, "%u.%u.%u.%u", (addr >> 24), (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
}

void inc_pkt_len(usage_t * u, int bytes)
{
	if (bytes < pkt_len[pkt_len_64]) {
		u->pkt_length[pkt_len_64]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_128]) {
		u->pkt_length[pkt_len_128]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_256]) {
		u->pkt_length[pkt_len_256]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_512]) {
		u->pkt_length[pkt_len_512]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_768]) {
		u->pkt_length[pkt_len_768]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_1024]) {
		u->pkt_length[pkt_len_1024]++;
		return;
	}
	if (bytes < pkt_len[pkt_len_1518]) {
		u->pkt_length[pkt_len_1518]++;
		return;
	} 
	else {
		u->pkt_length[pkt_len_jumbo]++;
		return;
	}

}

void inc_usage(usage_t * u, int bytes) 
{
	u->bytes += bytes;
	u->packets += 1;
}

void inc_bidi_usage(bidi_usage_t * bidi_u, int bytes, direction_t dir) 
{
	if(dir == C2S) {
		bidi_u->c2s.bytes += bytes;
		bidi_u->c2s.packets += 1;
		inc_pkt_len(&bidi_u->c2s, bytes);
		return;
	}
	if(dir == S2C) {
		bidi_u->s2c.bytes += bytes;
		bidi_u->s2c.packets += 1;
		inc_pkt_len(&bidi_u->s2c, bytes);
		return;
	}
}

void accumulate_usage(usage_t * to, usage_t * from) 
{
	to->bytes	+= from->bytes;
	to->packets	+= from->packets;
}

void accumulate_bidi_usage(bidi_usage_t * to, bidi_usage_t * from) 
{
	to->s2c.bytes	+= from->s2c.bytes;
	to->s2c.packets	+= from->s2c.packets;
	to->c2s.bytes	+= from->c2s.bytes;
	to->c2s.packets	+= from->c2s.packets;
}

void get_total_usage(usage_t * u) 
{
	USAGE_CLEAR_PTR(u);
	accumulate_usage(u, &cpmonitor_db.total_usage);
}

void accumulate_tcp_stats(tcp_stats_t * to, tcp_stats_t * from)
{	
	to->syn 				+= from->syn;
	to->syn_ack 			+= from->syn_ack; 				
	to->syn_push 			+= from->syn_push; 			
	to->syn_ack_push 		+= from->syn_ack_push; 		
	to->rst 				+= from->rst; 				
	to->rst_ack 			+= from->rst_ack; 			
	to->rst_ack_push	 	+= from->rst_ack_push; 		
	to->fin_ack 			+= from->fin_ack; 					
	to->ack 				+= from->ack; 				
	to->ack_push 			+= from->ack_push; 			
	to->ack_urg 			+= from->ack_urg; 			
	to->ack_urg_push 		+= from->ack_urg_push; 		
	to->fin_ack_push 		+= from->fin_ack_push; 		
	to->fin_ack_urg	 		+= from->fin_ack_urg; 				
	to->fin_ack_urg_push 	+= from->fin_ack_urg_push;
	to->invalid				+= from->invalid;
}

/* multitype typed hash */
static int is_keys_equal(hash_key_union_t * a, hash_key_union_t * b) 
{

#ifdef DEBUG
	if (!HASH_IS_TYPE_VALID(a)) {
		PRINTE("wrong key type %u\n", a->key_type);
	}
#endif
	if (a->key_type != b->key_type) {
		return 0;
	}

	switch (a->key_type) {			
	case HASH_IPV4_CONN:
		return (memcmp(a->data, b->data, sizeof(ipv4_fivetuple_t)) == 0);

	case HASH_IPV4_SERVER:
		return (memcmp(a->data, b->data, sizeof(ipv4_addr_t)) == 0);

	case HASH_SERVICE:
		return (memcmp(a->data, b->data, sizeof(service_t)) == 0);

	case HASH_IPV6_CONN:
		return (memcmp(a->data, b->data, sizeof(ipv6_fivetuple_t)) == 0);

	case HASH_IPV6_SERVER:
		return (memcmp(a->data, b->data, sizeof(ipv6_addr_t)) == 0);

	default:
		PRINTE("unexpected key type\n");
		return 0;
	}
}

static uint32 cpmonitor_hash_func(hash_key_union_t * a, int table_size) 
{
	uint32 i = 0;
	char * data = (char * ) a->data;

#ifndef DATA_MODEL_64
	uint32 hash = a->key_type;

	switch (a->key_type) {	
	case HASH_IPV4_CONN:
		for (; i + sizeof(uint32) <= sizeof(ipv4_fivetuple_t); i += sizeof(uint32)) {
			hash ^= *((uint32*)&data[i]);
		}
		break;

	case HASH_IPV4_SERVER:
		for (; i + sizeof(uint32) <= sizeof(ipv4_addr_t); i += sizeof(uint32)) {
			hash ^= *((uint32*)&data[i]);
		}
		break;

	case HASH_SERVICE:
		for (; i + sizeof(uint32) <= sizeof(service_t); i += sizeof(uint32)) {
			hash ^= *((uint32*)&data[i]);
		}
		break;

	case HASH_IPV6_CONN:
		for (; i + sizeof(uint32) <= sizeof(ipv6_fivetuple_t); i += sizeof(uint32)) {
			hash ^= *((uint32*)&data[i]);
		}
		break;

	case HASH_IPV6_SERVER:
		for (; i + sizeof(uint32) <= sizeof(ipv4_addr_t); i += sizeof(uint32)) {
			hash ^= *((uint32*)&data[i]);
		}
		break;

	default:
		return -1;
	}

#else /*DATA_MODEL_64*/
	uint64 hash = a->key_type;
	/* read chuncks in sizeof(uint64) to save reading cycles*/
	switch (a->key_type) {	
	case HASH_IPV4_CONN:
		for (; i + sizeof(uint64) <= sizeof(ipv4_fivetuple_t); i += sizeof(uint64)) {
			hash ^= *((uint64*)&data[i]);
		}
		break;

	case HASH_IPV4_SERVER:
		for (; i + sizeof(uint64) <= sizeof(ipv4_addr_t); i += sizeof(uint64)) {
			hash ^= *((uint64*)&data[i]);
		}
		break;

	case HASH_SERVICE:
		for (; i + sizeof(uint64) <= sizeof(service_t); i += sizeof(uint64)) {
			hash ^= *((uint64*)&data[i]);
		}
		break;

	case HASH_IPV6_CONN:
		for (; i + sizeof(uint64) <= sizeof(ipv6_fivetuple_t); i += sizeof(uint64)) {
			hash ^= *((uint64*)&data[i]);
		}
		break;

	case HASH_IPV6_SERVER:
		for (; i + sizeof(uint64) <= sizeof(ipv4_addr_t); i += sizeof(uint64)) {
			hash ^= *((uint64*)&data[i]);
		}
		break;

	default:
		return -1;
	}
#endif

	return hash % table_size;
}

static inline int hash_key_size(int key_t) 
{

	switch (key_t) {
	case HASH_IPV4_CONN:
		return sizeof(ipv4_fivetuple_t);

	case HASH_IPV6_CONN:
		return sizeof(ipv6_fivetuple_t);

	case HASH_IPV4_SERVER:
		return sizeof(ipv4_addr_t);

	case HASH_IPV6_SERVER:
		return sizeof(ipv6_addr_t);

	case HASH_SERVICE:
		return sizeof(service_t);

	default:
		PRINTE("wrong key_type %d\n", key_t);
	}
	return 0;
}

/* assume under lock */
void remove_ent_from_expire_list(cpmonitor_db_t * db, hash_entry_base_t * ent)
{
	if (ent->expire_prev) { /* not the first */
		ent->expire_prev->expire_next = ent->expire_next;	
	}
	else { /* the first */
		if (ent->expire_index != -1) { /* -1 means connection is new */
			db->hash_table.expire_ring[ent->expire_index % HISTORY_N] = ent->expire_next;
		}
	}
	if (ent->expire_next) {
		ent->expire_next->expire_prev = ent->expire_prev;
	}
	ent->expire_next = ent->expire_prev = NULL;
}

void move_to_current_expire_list(cpmonitor_db_t * db, hash_entry_base_t * ent) 
{
	hash_entry_base_t ** head;

#ifdef DEBUG	
	if (ent->expire_index > db->current_expire_index) {
		PRINTE("move_to_current_expire_list: ent->expire_index > table->current_expire_index\n");
		return;
	}
#endif

	if (ent->expire_index < db->current_expire_index) {	
		remove_ent_from_expire_list(db, ent);
		head = &db->hash_table.expire_ring[db->current_expire_index % HISTORY_N];
		ent->expire_next = *head;
		if (ent->expire_next) {
			ent->expire_next->expire_prev = ent;
		}
		*head = ent;
		ent->expire_index = db->current_expire_index;
		BIDI_USAGE_CLEAR(ent->bidi_usage_per_sec);

		if (HASH_IS_FIVETUPLE(ent)) {
			/* increase the number of connection we've seen during this current_expire_index (second) */
			db->summed_data[db->current_expire_index % HISTORY_N].connections++;
		}
	}	
}

/*
* the function will get the entry in the hash table.
* if add==TRUE and the entry does not exist it will be created.
*/
hash_entry_base_t * hash_ent_get(cpmonitor_db_t * db, hash_key_union_t * key, BOOL add)
{

	uint32 hash = cpmonitor_hash_func(key, db->hash_table.capacity);
	hash_entry_base_t * ent = NULL;

#ifdef DEBUG
	if (!HASH_IS_TYPE_VALID(key)) {
		PRINTE("wrong key type %u\n", key->key_type);
		return NULL;
	}
	if (hash == -1) {
		PRINTE("hash == -1\n");
		return NULL;		
	}
	if (db->hash_table.capacity <= hash ) {
		PRINTE("fivetuple_hash_table.capacity (%d) <= hash (%d)\n", db->hash_table.capacity, hash);
		return NULL;
	}
#endif

	ent = db->hash_table.hash[hash];
	while(ent != NULL && !is_keys_equal(HASH_ENT_TO_KEY(ent), key)) {
		ent = ent->hash_next;
	}

	if(ent == NULL) {
		if(!add) {
			return NULL;
		}		
		/* create a new one at the head, if there is room in this hash */
		if (LIKELY(db->hash_table.count < (cpmonitor_conf.connection_table_size * 10))) {
			ent = (hash_entry_base_t *) MALLOC(sizeof(*ent) + hash_key_size(key->key_type));
			if (ent == NULL) {
				PRINTE("MALLOC failed allocating a new entry in the table.\n\n\n");
				return NULL;
			}
		} else {
			PRINTE("Exceeded the desired table size. Please re-run the tool and use -c flag to allocate more memory for the table.\n\n\n");
			return NULL;
		}	

		/* init by the order in the struct */
		ent->expire_index 	= -1;
		ent->expire_prev 	= NULL;
		ent->expire_next 	= NULL;
		ent->hash_next = db->hash_table.hash[hash];
		db->hash_table.hash[hash] = ent;
		ent->top_ent_index 	= -1;

		/* new connection -> add it to cps */
		if (HASH_IS_FIVETUPLE(key)) {
			db->summed_data[db->current_expire_index % HISTORY_N].cps++;
		}

		BIDI_USAGE_CLEAR(ent->overall_usage);
		ent->syn_cnt = 0;

		BIDI_USAGE_CLEAR(ent->bidi_usage_per_sec);
		memcpy(&ent->key_type, key, hash_key_size(key->key_type) + sizeof(hash_type_u));	

		db->hash_table.count++;
	}

	move_to_current_expire_list(db, ent);

	return ent;
}


int hash_init(hash_table_t* table, uint32 size)
{
	uint32 hash_allocation_size = 0;
	short hash_struct_size = sizeof(table->hash);

	memset(table, 0, sizeof(*table));

	do {
		hash_allocation_size = size * hash_struct_size;
		PRINTD("Hash struct size is: %d, wanted num of entries in the table: %d, requested allocation size: %d\n", hash_struct_size, size, hash_allocation_size);

		table->hash = (hash_entry_base_t **)MALLOC(hash_allocation_size);
		if (table->hash != NULL) {
			break;
		}
		PRINT("size %d is too big, retry...\n", size);
		size /= 10;
	} while (size > 10000);

	if (table->hash == NULL) {
		PRINTE("failed to alloc hash_table_t (size %d)\n\n\n", size);
		return -1;
	}

	PRINTD("Successfully allocated %d bytes for hash table\n", hash_allocation_size);
	memset(table->hash, 0, hash_allocation_size);
	table->capacity = size;
	return 0;
}

void hash_free(hash_table_t * table) 
{
	uint32 i = 0;
	hash_entry_base_t * ent = NULL;
	hash_entry_base_t * tmp = NULL;

	for (i = 0 ; i < table->capacity ; i++) {
		ent = table->hash[i];
		while (ent != NULL) {
			tmp = ent;
			ent = ent->hash_next;
			FREE(tmp);
		}
	}
	FREE(table->hash);
}

void hash_table_inc_timeslot(cpmonitor_db_t * db, struct timeval * tv)
{
	hash_entry_base_t * ent;
	top_ent_t * top_ents_arr;
	int i;
	int top_kind;

#ifdef DEBUG
	if (!db) {
		PRINTE("db is NULL\n");
	}
	if (!tv) {
		PRINTE("tv is NULL\n");
	}	
#endif 

	/* clear the next top N tables and total_usage_per_sec for next round */
	memset(&db->summed_data[(db->current_expire_index+1) % HISTORY_N], 0, sizeof(db->summed_data[0]));

	db->summed_data[db->current_expire_index % HISTORY_N].time_end = *tv;

	/* incr expire index */	
	db->current_expire_index++;

	db->summed_data[db->current_expire_index % HISTORY_N].time_start = *tv;

	/* save top N data for this timeslot */
	for (top_kind = 0; top_kind < TOP_COUNT; top_kind++) {
		top_ents_arr = db->summed_data[(db->current_expire_index-1) % HISTORY_N].top_ents[top_kind];
		for (i=TOP_N-1; i>=0; i--) {
			ent = top_ents_arr[i].ent;
			if (!ent) 
				break;
			memcpy(&top_ents_arr[i].key, &top_ents_arr[i].ent->key_type, sizeof(hash_type_u) + hash_key_size(top_ents_arr[i].ent->key_type));
			ent->top_ent_index = -1;
		}
	}
}

//#define BUBLE_SORT_DEBUG  // uncomment this for debuging

void hash_ent_put_in_top_ents(cpmonitor_db_t * db, hash_entry_base_t * ent)
{
	int packets;
	uint64 bytes;
	int i;
	top_ent_t * top_ents;

	switch (ent->key_type) {
	case HASH_IPV4_CONN:
	case HASH_IPV6_CONN:
		top_ents = db->summed_data[db->current_expire_index % HISTORY_N].top_ents[TOP_CONNS];		
		break;

	case HASH_IPV4_SERVER:
	case HASH_IPV6_SERVER:	
		top_ents = db->summed_data[db->current_expire_index % HISTORY_N].top_ents[TOP_SERVERS];
		break;

	case HASH_SERVICE:
		top_ents = db->summed_data[db->current_expire_index % HISTORY_N].top_ents[TOP_SERVICES];
		break;
	default:		
		PRINTE("Error, hash_ent_inc_usage: bad ent->key_type %d\n", ent->key_type);
		return;		
	}

	packets = bidi_total_packets(&ent->bidi_usage_per_sec);
	bytes = bidi_total_bytes(&ent->bidi_usage_per_sec);
	if (ent->top_ent_index >= 0) {
		i = ent->top_ent_index;
		top_ents[i].bidi_usage= ent->bidi_usage_per_sec;

#ifdef DEBUG
		if (top_ents[i].ent != ent) {
			PRINTE("top_ents[i=%d].ent != ent\n", i);
		}
#endif

		i++; /* this means compare the i+1 to this ent */

#ifdef BUBLE_SORT_DEBUG		
		if (ent->key_type == HASH_IPV4_CONN) {
			PRINT("DEBUG: old (%d) (table->current_expire_index %d) %x:%d -> %x:%d %u  ", i, db->current_expire_index,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.src_ip,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.sport,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.dst_ip,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.dport,
				packets);
		}
#endif		

	}
	else {
		i = 0;
		/* find the first non occupied top_ent (usually all are occupied) */
		while ((i+1<TOP_N) && (top_ents[i+1].ent == NULL)) {
			i++;
		}		

#ifdef BUBLE_SORT_DEBUG			
		if (ent->key_type == HASH_IPV4_CONN) {
			PRINT("DEBUG: new (%d) (table->current_expire_index %d) %x:%d -> %x:%d %u  ", i, db->current_expire_index,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.src_ip,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.sport,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.dst_ip,
				HASH_ENT_TO_KEY(ent)->conn_ipv4.dport,
				packets);
		}
#endif
	}


	/* compare to each entry and do buble sort */
	while (i < TOP_N) {

		if (cpmonitor_conf.sort_method == sort_method_packets) {
			if (bidi_total_packets(&top_ents[i].bidi_usage) >= packets) {
				break;
			}
		}
		else if (bidi_total_bytes(&top_ents[i].bidi_usage) >= bytes) {
			break;
		}

#ifdef BUBLE_SORT_DEBUG			
		if (ent->key_type == HASH_IPV4_CONN) {	
			PRINT(" [-> %d] ", i);
		}
#endif		

		if (i==0) {
			/* push the last one out */
			if (top_ents[0].ent) {
				top_ents[0].ent->top_ent_index--;
			}		
		}
		else {
			top_ents[i-1].ent = top_ents[i].ent;
			top_ents[i-1].bidi_usage = top_ents[i].bidi_usage;
			if (top_ents[i-1].ent) {
				top_ents[i-1].ent->top_ent_index--;
			}
		}

		top_ents[i].bidi_usage = ent->bidi_usage_per_sec;
		top_ents[i].ent = ent;
		ent->top_ent_index = i;

		i++;
	}
#ifdef BUBLE_SORT_DEBUG		
	if (ent->key_type == HASH_IPV4_CONN) {
		PRINT("\n");
	}
#endif
}

static void hash_ent_inc_usage(cpmonitor_db_t * db, hash_entry_base_t * ent, int size, int dir, BOOL is_syn)
{
	inc_bidi_usage(&ent->overall_usage, size, dir);
	if(UNLIKELY(is_syn)) {
		ent->syn_cnt++;
	}

	inc_bidi_usage(&ent->bidi_usage_per_sec, size, dir);

	hash_ent_put_in_top_ents(db, ent);
}

static void switch_src_dest(int ip_ver, hash_key_union_t * conn, hash_key_union_t * host)
{
	ip_union_t temp_addr;
	uint16 temp_port;

	if (ip_ver == 4) {
		temp_addr.ipv4 			= conn->conn_ipv4.src_ip;
		temp_port 				= conn->conn_ipv4.sport;
		conn->conn_ipv4.src_ip 	= conn->conn_ipv4.dst_ip;
		conn->conn_ipv4.sport 	= conn->conn_ipv4.dport;
		conn->conn_ipv4.dst_ip 	= temp_addr.ipv4;
		conn->conn_ipv4.dport 	= temp_port;
		host->ipv4 				= conn->conn_ipv4.dst_ip;
	}
	else {
		temp_addr.ipv6 			= conn->conn_ipv6.src_ip;
		temp_port 				= conn->conn_ipv6.sport;
		conn->conn_ipv6.src_ip 	= conn->conn_ipv6.dst_ip;
		conn->conn_ipv6.sport 	= conn->conn_ipv6.dport;
		conn->conn_ipv6.dst_ip 	= temp_addr.ipv6;
		conn->conn_ipv6.dport 	= temp_port;
		host->ipv6 				= conn->conn_ipv6.dst_ip;
	}
}

static void conn_host_creator(hash_key_union_t * conn, hash_key_union_t * host, int ip_ver, ip_union_t * source, ip_union_t * dest, u_int sport, u_int dport, u_char proto)
{
	if (ip_ver == 4) {
		conn->key_type = HASH_IPV4_CONN;
		conn->conn_ipv4.src_ip = source->ipv4;
		conn->conn_ipv4.sport = sport;
		conn->conn_ipv4.dst_ip = dest->ipv4;
		conn->conn_ipv4.dport = dport;
		conn->conn_ipv4.ipproto = proto;

		host->key_type = HASH_IPV4_SERVER;
		host->ipv4 = conn->conn_ipv4.dst_ip;
	}
	else {
		conn->key_type = HASH_IPV6_CONN;
		conn->conn_ipv6.src_ip = source->ipv6;
		conn->conn_ipv6.sport = sport;
		conn->conn_ipv6.dst_ip = dest->ipv6;
		conn->conn_ipv6.dport = dport;
		conn->conn_ipv6.ipproto = proto;

		host->key_type = HASH_IPV6_SERVER;
		host->ipv6 = conn->conn_ipv6.dst_ip;

	}
}

static void service_creator(hash_key_union_t * service, uint8 ipproto, uint16 sport, uint16 dport, int size, direction_t dir)
{
	service->key_type = HASH_SERVICE;
	service->service.ipproto = ipproto;

	if(dir == S2C) {
		service->service.port = sport;
	}
	else {
		service->service.port = dport;
	}
}

/* counting functions */
static int connection_count(int ip_ver, ip_union_t * source, ip_union_t * dest, u_int sport, u_int dport, u_char proto,
							int size, BOOL is_syn, char i_o, char * if_desc, short vlan_id, uint32 ip_id, uint16 proto_checksum, struct timeval * ts)
{
	hash_entry_base_t * ent = NULL;
	hash_key_union_t 	conn;
	hash_key_union_t 	host;
	hash_key_union_t 	service;
	direction_t  		dir = C2S;
	BOOL				is_error = FALSE;
	char 				src_ip_buff[IP_BUFF_SIZE] = {0};
	char 				dst_ip_buff[IP_BUFF_SIZE] = {0};

	memset(&conn, 0, sizeof(conn));
	memset(&host, 0, sizeof(host));	
	memset(&service, 0, sizeof(service));

	inc_usage(&cpmonitor_db.total_usage, size);
	inc_usage(&cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].total_usage, size);

	/* connection */
	if (UNLIKELY(is_syn)) {
		conn_host_creator(&conn, &host, ip_ver, source, dest, sport, dport, proto);
		dir = C2S;
		ent = hash_ent_get(&cpmonitor_db, &conn, TRUE);
	}
	else {
		if (sport < dport) {
			conn_host_creator(&conn, &host, ip_ver, source, dest, sport, dport, proto);
			dir = C2S;
		}
		else {
			conn_host_creator(&conn, &host, ip_ver, dest, source, dport, sport, proto);
			dir = S2C;
		}
		ent = hash_ent_get(&cpmonitor_db, &conn, FALSE);
		if (ent == NULL) {
			/* connection did not exist, might exist other way around */
			switch_src_dest(ip_ver, &conn, &host);

			dir = (dir == C2S) ? S2C : C2S;
			ent = hash_ent_get(&cpmonitor_db, &conn, TRUE);	
		}
	}

	if (ent == NULL) {
		PRINTD("Failed acquiring connection entry from the table.\n");
		is_error = TRUE;
	}
	else {
		hash_ent_inc_usage(&cpmonitor_db, ent, size, dir, is_syn);

		/* host */
		ent = hash_ent_get(&cpmonitor_db, &host, TRUE);
		if (ent == NULL) {
			PRINTD("Failed acquiring host entry from the table.\n");
			is_error = TRUE;
		}
		else {
			hash_ent_inc_usage(&cpmonitor_db, ent, size, dir, is_syn);

			/* service */
			service_creator(&service, proto, sport, dport, size, dir);
			ent = hash_ent_get(&cpmonitor_db, &service, TRUE);
			if (ent == NULL) {
				PRINTD("Failed acquiring service entry from the table.\n");
				is_error = TRUE;
			}
			else {
				hash_ent_inc_usage(&cpmonitor_db,  ent, size, dir, is_syn);
			}
		}
	}

	if (cpmonitor_conf.debug) {
		if (ip_ver == 4) {
			ipv4_to_str(source->ipv4, src_ip_buff, sizeof(src_ip_buff));
			ipv4_to_str(dest->ipv4, dst_ip_buff, sizeof(dst_ip_buff));
			PRINT("src ip: %s | dst ip: %s | src port: %d | dst port: %d | proto: %d | is syn: %s | dir: %s | i_o: %c | iface: %s | vlan_id: %d | ip_id: %d | proto checksum: 0x%04x | timestamp: %ld.%09ld | \n",
				src_ip_buff, dst_ip_buff, sport, dport, proto, (is_syn == 1)?"yes":"no", (dir == C2S)?"C2S":"S2C", i_o, (if_desc == NULL)?"NULL":(if_desc), vlan_id, ip_id, proto_checksum, ts->tv_sec, ts->tv_usec);
		}
		else {
			ipv6_to_str(&(source->ipv6), src_ip_buff, sizeof(src_ip_buff));
			ipv6_to_str(&(dest->ipv6), dst_ip_buff, sizeof(dst_ip_buff));
			PRINT("src ip: %s | dst ip: %s | src port: %d | dst port: %d | proto: %d | is syn: %s | dir: %s | i_o: %c | iface: %s | vlan_id: %d | ip_id: %d | proto checksum: 0x%04x | timestamp: %ld.%09ld | \n",
				src_ip_buff, dst_ip_buff, sport, dport, proto, (is_syn == 1)?"yes":"no", (dir == C2S)?"C2S":"S2C", i_o, (if_desc == NULL)?"NULL":(if_desc), vlan_id, ip_id, proto_checksum, ts->tv_sec, ts->tv_usec);
		}
	}

	if (is_error) {
		return -1;
	}

	return 0;
}

static int parse_tcp(tcphdr_t * tcphdr, BOOL * is_syn) 
{
	summed_data_t * summed_data = &cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N];
	*is_syn = FALSE;
	switch (tcphdr->th_flags & ~(TH_ECE|TH_CWR)) {
	case (TH_ACK): 							summed_data->tcp_stats.ack++; 				break;
	case (TH_ACK|TH_PUSH): 					summed_data->tcp_stats.ack_push++; 			break;
	case (TH_ACK|TH_URG): 					summed_data->tcp_stats.ack_urg++; 			break;
	case (TH_ACK|TH_URG|TH_PUSH): 			summed_data->tcp_stats.ack_urg_push++; 		break;
	case (TH_SYN): 							summed_data->tcp_stats.syn++; 				*is_syn = TRUE;	break;
	case (TH_SYN|TH_ACK): 					summed_data->tcp_stats.syn_ack++; 			break;
	case (TH_SYN|TH_PUSH): 					summed_data->tcp_stats.syn_push++; 			break;
	case (TH_SYN|TH_ACK|TH_PUSH): 			summed_data->tcp_stats.syn_ack_push++; 		break;
	case (TH_RST): 							summed_data->tcp_stats.rst++; 				break;
	case (TH_FIN): 			 				break;
	case (TH_RST|TH_ACK): 					summed_data->tcp_stats.rst_ack++; 			break;
	case (TH_RST|TH_ACK|TH_PUSH): 			summed_data->tcp_stats.rst_ack_push++; 		break;
	case (TH_FIN|TH_ACK): 					summed_data->tcp_stats.fin_ack++; 			break;
	case (TH_FIN|TH_ACK|TH_PUSH): 			summed_data->tcp_stats.fin_ack_push++; 		break;
	case (TH_FIN|TH_ACK|TH_URG): 			summed_data->tcp_stats.fin_ack_urg++; 		break;
	case (TH_FIN|TH_ACK|TH_URG|TH_PUSH):	summed_data->tcp_stats.fin_ack_urg_push++; 	break;
	default:
		PRINTE("unknown tcp flag %x\n", tcphdr->th_flags & ~(TH_ECE|TH_CWR));
		summed_data->tcp_stats.invalid++;
		return -1;
	}

	return 0;
}


static int get_ports_tcp(tcphdr_t * tcp, uint16* sport, uint16* dport, int caplen, BOOL * is_syn, uint16 * proto_checksum)
{
	if(parse_tcp(tcp, is_syn) < 0) {
		return -1;
	}

	*sport = ntohs(tcp->th_sport);
	*dport = ntohs(tcp->th_dport);

	*proto_checksum = ntohs(tcp->th_sum);

	return 0;
}

static void get_ports_udp(udphdr_t * udp, uint16* sport, uint16* dport, uint16 * proto_checksum)
{
	*sport = ntohs(udp->source);
	*dport = ntohs(udp->dest);

	*proto_checksum = ntohs(udp->check);
}

static void get_ports_sctp(sctphdr_t * sctp, uint16* sport, uint16* dport, uint16 * proto_checksum)
{
	*sport = ntohs(sctp->source_port);
	*dport = ntohs(sctp->dest_port);

	*proto_checksum = ntohs(sctp->check);
}

static void get_ports_esp(esphdr_t * esp, uint16* sport, uint16* dport, uint16 * proto_checksum)
{
	*sport = (uint16)-1;
	*dport = (uint16)-1;

	/* esp has no checksum in its header */
	*proto_checksum = 0;
}

static void get_ports_icmp(icmphdr_t * icmp, uint16* sport, uint16* dport, uint16 * proto_checksum)
{
	*sport = icmp->port;
	*dport = (uint16)-1;

	*proto_checksum = ntohs(icmp->checksum);
}

void print_unsupported_ipproto_counters()
{
	PRINT("small_IPV4HDR_LEN: %d\n", small_IPV4HDR_LEN);
	PRINT("IPV4_FRAG_not_IPPROTO_ESP_SCTP: %d\n", IPV4_FRAG_not_IPPROTO_ESP_SCTP);
	PRINT("small_IPV6HDR_LEN: %d\n", small_IPV6HDR_LEN);
	PRINT("IPV6_FRAG_not_IPPROTO_ESP_SCTP: %d\n", IPV6_FRAG_not_IPPROTO_ESP_SCTP);
	PRINT("unsupported_ip: %d\n", unsupported_ip);
	PRINT("small_icmphdr_t: %d\n", small_icmphdr_t);
	PRINT("small_tcphdr_t: %d\n", small_tcphdr_t);
	PRINT("unknown_tcp_flag: %d\n", unknown_tcp_flag);
	PRINT("small_udphdr_t: %d\n", small_udphdr_t);
	PRINT("small_esphdr_t: %d\n", small_esphdr_t);
	PRINT("small_sctphdr_t: %d\n", small_sctphdr_t);
	PRINT("unsupported_ipproto: %d\n", unsupported_ipproto);
}

int parse_entry(void * data, int size, uint32 cap_len, struct timeval * ts, char i_o, char * if_desc, short vlan_id)
{
	int 			ip_ver = 0;
	void *			next_hdr = NULL;
	ipproto_t		ipproto = {0};
	uint16 			sport = 0, dport = 0;
	ip_union_t		src = {0}, dst = {0};
	int 			ip_hdr_len = 0;
	BOOL			is_syn = FALSE;
	uint32			ip_id = 0;
	uint16			proto_checksum = 0;
	BOOL			is_unsupported = FALSE;

	ip_ver = IP_VER(data);
	ip_id = IP_ID(ip_ver, data);

	if (ip_ver == 4) {
		if (UNLIKELY(cap_len < IPV4HDR_LEN(data))) {
			is_unsupported = TRUE;
			PRINTD("found a small IPV4HDR_LEN. ");
			small_IPV4HDR_LEN++;
		}
		else {
			ipproto 	= IPV4_P(data);
			if (IPV4_IS_FRAG(data) && ((ipproto != IPPROTO_ESP) || (ipproto != IPPROTO_SCTP))) {
				/* don't handle fragments */
				is_unsupported = TRUE;
				PRINTD("found a IPV4_IS_FRAG and not IPPROTO_ESP / IPPROTO_SCTP. ipproto is: %d. ", ipproto);
				IPV4_FRAG_not_IPPROTO_ESP_SCTP++;
			}
			else {
				ip_hdr_len 	= IPV4HDR_LEN(data);
				src.ipv4 	= IPV4_SRC(data);
				dst.ipv4 	= IPV4_DST(data);
			}
		}
	}
	else if (ip_ver == 6) {
		if (UNLIKELY(cap_len < IPV6HDR_LEN(data))) {
			is_unsupported = TRUE;
			PRINTD("found a small IPV6HDR_LEN. ");
			small_IPV6HDR_LEN++;
		}	
		else {
			ipproto 	= IPV6_P(data);
			if (IPV6_IS_FRAG(data) && ((ipproto != IPPROTO_ESP) || (ipproto != IPPROTO_SCTP))) {
				/* don't handle fragments */
				is_unsupported = TRUE;
				PRINTD("found a IPV6_IS_FRAG and not IPPROTO_ESP / IPPROTO_SCTP. ipproto is: %d. ", ipproto);
				IPV6_FRAG_not_IPPROTO_ESP_SCTP++;
			}
			else {
				ip_hdr_len 	= IPV6HDR_LEN(data);
				src.ipv6 	= IPV6_SRC(data);
				dst.ipv6 	= IPV6_DST(data);
			}
		}
	}
	else {
#ifdef DEBUG
		extern uint64 entry_counter;
		PRINT("Warn: ip version %d not supported (#%llu)\n", ip_ver, entry_counter);
#endif		
		is_unsupported = TRUE;
		PRINTD("found a unsupported ip version.  ip_ver is: %d. ", ip_ver);
		unsupported_ip++;
	}

	if (!is_unsupported) {
		next_hdr = data + ip_hdr_len;

		switch (ipproto) {
		case IPPROTO_ICMP:
		case IPV6PROTO_ICMP:
			is_syn = FALSE;
			if (UNLIKELY(cap_len < (sizeof(icmphdr_t) + ip_hdr_len))) {
				is_unsupported = TRUE;
				PRINTD("found a small icmphdr_t. ");
				small_icmphdr_t++;
			}
			else {
				get_ports_icmp((icmphdr_t *)next_hdr, &sport, &dport, &proto_checksum);
			}
			break;

		case IPPROTO_TCP:
			if (UNLIKELY(cap_len < ( sizeof(tcphdr_t) + ip_hdr_len))) {
				is_unsupported = TRUE;
				PRINTD("found a small tcphdr_t. ");
				small_tcphdr_t++;
			}
			else if (get_ports_tcp((tcphdr_t *)next_hdr, &sport, &dport, cap_len - ip_hdr_len, &is_syn, &proto_checksum) < 0) {
				is_unsupported = TRUE;
				PRINTD("found an unknown tcp flag. ");
				unknown_tcp_flag++;
			}
			break;
		case IPPROTO_UDP:
			is_syn = FALSE;
			if (UNLIKELY(cap_len < (sizeof(udphdr_t) + ip_hdr_len))) {
				is_unsupported = TRUE;
				PRINTD("found a small udphdr_t. ");
				small_udphdr_t++;
			}
			else {
				get_ports_udp((udphdr_t *)next_hdr, &sport, &dport, &proto_checksum);
			}
			break;
		case IPPROTO_ESP:
			is_syn = FALSE;
			if (UNLIKELY(cap_len < (sizeof(esphdr_t) + ip_hdr_len))) {
				is_unsupported = TRUE;
				PRINTD("found a small esphdr_t. ");
				small_esphdr_t++;
			}
			else {
				get_ports_esp((esphdr_t *)next_hdr, &sport, &dport, &proto_checksum);
			}
			break;
		case IPPROTO_SCTP:
			is_syn = FALSE;
			if (UNLIKELY(cap_len < (sizeof(sctphdr_t) + ip_hdr_len))) {
				is_unsupported = TRUE;
				PRINTD("found a small sctphdr_t. ");
				small_sctphdr_t++;
			}
			else {
				get_ports_sctp((sctphdr_t *)next_hdr, &sport, &dport, &proto_checksum);
			}
			break;
		default:
			is_syn = FALSE;
			is_unsupported = TRUE;
			PRINTD("found a unsupported ipproto. ipproto is: %d. ", ipproto);
			unsupported_ipproto++;
			break;
		}
	}

	if (is_unsupported) {
		cpmonitor_db.summed_data[cpmonitor_db.current_expire_index % HISTORY_N].unsupported_entries++;
		PRINTD("unsupported entry with ip_id: %d\n", ip_id);
	}
	else {
		if ((ip_id > MAX_IP_ID) || (ip_id < 0)) {
			PRINTD("got invalid ip id: %d. setting ip id to 0.\n", ip_id);
			ip_id = 0;
		}

		return connection_count(ip_ver, &src, &dst, sport, dport, ipproto, size, is_syn, i_o, if_desc, vlan_id, ip_id, proto_checksum, ts);
	}

	return 0;
}

/* init and fini */
int core_init() 
{
	memset(&cpmonitor_db, 0, sizeof(cpmonitor_db));

	if (offsetof(hash_entry_base_t, data) - offsetof(hash_entry_base_t, key_type) != offsetof(hash_key_union_t, ipv4)) {
		PRINTE("data structures alignment error\n\n\n");
		return -1;
	}

	PRINTD("Before allocating the hash table. connection_table_size is: %d\n", cpmonitor_conf.connection_table_size);
	if (hash_init(&cpmonitor_db.hash_table, cpmonitor_conf.connection_table_size)) {
		PRINTE("Failed allocating fivetuple hash memory\n\n\n");
		return -1;
	}

	return 0;
}

void core_fini() 
{
	hash_free(&cpmonitor_db.hash_table);		
}

