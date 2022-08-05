#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/* ETHERNET HEADER */
struct libnet_ethernet_hdr
{
        u_int8_t  ether_dhost[6];/* destination ethernet address */
        u_int8_t  ether_shost[6];/* source ethernet address */
        u_int16_t ether_type;                 /* protocol */
};

/* IP HEADER */
struct libnet_ipv4_hdr
{
        struct libnet_ethernet_hdr ether;
        u_int8_t ip_v:4,       /* version */
        ip_hl:4;        /* header length */

        u_int8_t ip_tos;       /* type of service */

        u_int16_t ip_len;         /* total length */
        u_int16_t ip_id;          /* identification */
        u_int16_t ip_off;

        u_int8_t ip_ttl;          /* time to live */
        u_int8_t ip_p;            /* protocol */
        u_int16_t ip_sum;         /* checksum */

	u_int8_t ip_src[4], ip_dst[4];
};

/* TCP HEADER */
struct libnet_tcp_hdr
{
        struct libnet_ipv4_hdr ipv4;
        u_int16_t th_sport;       /* source port */
        u_int16_t th_dport;       /* destination port */
         u_int32_t th_seq;          /* sequence number */
        u_int32_t th_ack;          /* acknowledgement number */

        u_int8_t th_off:4,        /* data offset */
                th_x2:4;         /* (unused) */

        u_int8_t  th_flags;       /* control flags */

        u_int16_t th_win;         /* window */
        u_int16_t th_sum;         /* checksum */
        u_int16_t th_urp;         /* urgent pointer */
};
struct libnet_http_hdr

{

    u_int8_t HTP[16];

};


typedef struct 
{
	char* dev;
} Param;

Param param = {
	.dev = NULL
};

void printEthernet(const u_char *packet)
{	
	struct libnet_ethernet_hdr* e;
	e = (struct libnet_ethernet_hdr *)packet;
	printf("Src Mac : %02x:%02x:%02x:%02x:%02x:%02x \n", e->ether_shost[0],e->ether_shost[1],e->ether_shost[2],e->ether_shost[3],e->ether_shost[4],e->ether_shost[5]);
	printf("Dst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", e->ether_dhost[0],e->ether_dhost[1],e->ether_dhost[2],e->ether_dhost[3],e->ether_dhost[4],e->ether_dhost[5]);
}

void printIp(const u_char *packet)
{
	struct libnet_ipv4_hdr* i;
	i = (struct libnet_ipv4_hdr*)packet;
	printf("Src IP : %d.%d.%d.%d\n", i->ip_src[0],i->ip_src[1],i->ip_src[2],i->ip_src[3]);
	printf("Dst IP : %d.%d.%d.%d\n", i->ip_dst[0],i->ip_dst[1],i->ip_dst[2],i->ip_dst[3]);
}

void printPort(const u_char *packet)
{
	struct libnet_tcp_hdr* t;
	t = (struct libnet_tcp_hdr*)packet;
	printf("Src port : %d\n", ntohs(t->th_sport));
	printf("Dst port : %d\n", ntohs(t->th_dport));
}

void printData(const u_char *packet)
{
	struct libnet_http_hdr* h;
	h = (struct libnet_http_hdr*)packet;
	printf("Data : ");
	for (int i = 0; i < 10; i++)
	{
		printf("%02x ",h->HTP[i]);
	}
}

bool boo1(Param* param, int argc, char* argv[])
{
	if (argc != 2)
	{
		return false;
	}
	param -> dev = argv[1];
	return true;
}

int main(int argc, char* argv[])
{
	if (!boo1(&param, argc, argv))
	{
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL)
	{
		printf("error");
		return -1;
	}
	while (1)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
			return -1;
		u_int l;
		struct libnet_ethernet_hdr *e = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)packet;
		struct libnet_tcp_hdr *t = (struct libnet_tcp_hdr*)packet;
		if (e->ether_type==0x08)
		{
			if (ip->ip_p==0x06)
			{
				printf("==================================\n\n");
				printEthernet(packet);
				printIp(packet);
				printPort(packet);
				l = 14+(ip->ip_hl)+(t->th_off);
				//printf("%d\n",l);
				packet+=l;
				printData(packet);
				printf("\n\n");
			}
		}
	}
	pcap_close(pcap);
}
