#ifndef _UTILS_H_
#define _UTILS_H_

#include <pcap.h>

#include "T.h"

typedef struct ip_address {
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;

} ip_address;

typedef struct client_s {
	struct client_s* next;

	unsigned long ip;
	unsigned short port;

	int node;
	unsigned long node_ip;
	unsigned short node_port;

	unsigned int shakeID;
	unsigned int lastPingID;

	T_t pingTimeout;
	T_t pingInterval;

} client_t;

/* IPv4 header */
typedef struct ip_header {
	u_char	ver_ihl;		/* Version (4 bits) + Internet header length (4 bits) */
	u_char	tos;			/* Type of service */
	u_short tlen;			/* Total length */
	u_short identification; /* Identification */
	u_short flags_fo;		/* Flags (3 bits) + Fragment offset (13 bits) */
	u_char	ttl;			/* Time to live */
	u_char	proto;			/* Protocol */
	u_short crc;			/* Header checksum */
	ip_address	saddr;		/* Source address */
	ip_address	daddr;		/* Destination address */
	u_int	op_pad;			/* Option + Padding */

} ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;			/* Source port */
	u_short dport;			/* Destination port */
	u_short len;			/* Datagram length */
	u_short crc;			/* Checksum */

} udp_header;

extern unsigned short ip_sum_calc( unsigned short len_ip_header, unsigned char buff[] );
extern pcap_t* open_iface( pcap_if_t* d );
extern pcap_if_t* get_iface( char* desc, pcap_if_t* alldevs );
extern pcap_if_t* get_alldevs( void );
extern int free_alldevs( pcap_if_t* alldevs );

#endif /* _UTILS_H_ */
