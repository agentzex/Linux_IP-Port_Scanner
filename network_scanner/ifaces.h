#ifndef _IFACES_H
#define _IFACES_H


#ifdef __cplusplus
extern "C"
{
#endif

#include <pcap.h>
#include <netinet/ether.h>
#include "data_al.h"


/* If system is Solaris */
#if defined(sun) && (defined(__svr4__) || defined(__SVR4))
#define PCAP_TOUT 20
      typedef uint64_t u_int64_t;
      typedef uint32_t u_int32_t;
      typedef uint16_t u_int16_t;
      typedef uint8_t  u_int8_t;
#else
#define PCAP_TOUT 0
#endif


char errbuf[PCAP_ERRBUF_SIZE];

/* Threads data structure */
struct t_data {
    char const *interface;
    char *source_ip;
    char *pcap_filter;
    struct ether_addr **ignore_macs;
};

/* Sniffer/Packet processing Functions */
void *start_sniffer(void *);
void process_arp_header(struct data_registry *, const u_char *);
void process_packet(u_char *, struct pcap_pkthdr *, const u_char *);

/* ARP Generation & Injection */
int inject_init(char const *);
void forge_arp(char *, char *);
void inject_destroy();
void break_pcap_loop();

#ifdef __cplusplus
}
#endif

#endif /* _IFACES_H */