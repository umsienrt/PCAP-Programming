#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader{
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader{
	unsigned char iph_ihl:4,
		      iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3,
			   iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

struct tcpheader{
	u_short tcp_sport;
	u_short tcp_dport;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char tcp_offx2;
#define TH_OFF(th)(((th)->tcp_offx2 & 0xf0) >> 4)
	u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

void hexdump(const u_char *data, int length){
	int i;
	printf("Message: ");
	for(i=0;i<length;i++){
		printf("%02x", data[i]);
		if((i+1) % 16 == 0){
			printf("\n");
		}
	}
	printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	if(ntohs(eth->ether_type) == 0x0800){
		struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

		printf("Ethernet src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
			eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
		printf("Ethernet dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth-> ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
			eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

		printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("dst ip: %s\n", inet_ntoa(ip->iph_destip));


		struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader)+sizeof(struct ipheader));
		printf("TCP src port: %u\n", ntohs(tcp->tcp_sport));
		printf("TCP dst port: %u\n", ntohs(tcp->tcp_dport));

		int headersum_len = sizeof(struct ethheader) +  sizeof(struct ipheader) + (TH_OFF(tcp) * 4);
		int message_len = header -> len - headersum_len;

		hexdump(packet + headersum_len, message_len);
		printf("-------------------------------------------------\n");
	}
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	if(pcap_setfilter(handle, &fp) != 0){
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);

	return 0;
}
