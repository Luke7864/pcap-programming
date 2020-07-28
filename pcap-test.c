//Written By Jaeuk Shin
//2020.07.28.
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

//IP Header struct
struct ip * iph;

//TCP Header Struct
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	struct ether_header *ep;
	unsigned short ether_type;
	int chcnt = 0;
	int length = pkthdr -> len;

	//Get Ethernet Header
	ep = (struct ether_header *)packet;

	//Get Ip header
	//Find Ethernet header by offset
	packet += sizeof(struct ether_header);

	//Get Protocol Type
	ether_type = ntohs(ep->ether_type);

	//If it has IP Packet
	if (ether_type == ETHERTYPE_IP) {
		printf("Ethernet INFO\n");
		printf("Src Mac Address: ");
		for (int i=0; i<6; ++i){
			printf("%.2X", ep->ether_shost[i]);
			if (i!=5){
				printf(":");
			}
		}
		printf("\n");
		printf("Dst Mac Address: ");
		for (int i=0; i<6; ++i){
			printf("%.2X", ep->ether_dhost[i]);
			if(i!=5){
				printf(":");
			}
		}
		printf("\n\n");

		printf("IP INFO\n");
		iph = (struct ip *)packet;
		printf("IP Packet:\n");
		printf("Version: %d\n", iph->ip_v);
		printf("Header Len: %d\n", iph->ip_hl);
		printf("Ident: %d\n", ntohs(iph->ip_id));
		printf("TTL: %d\n", iph->ip_ttl);
		printf("Src Address: %s\n", inet_ntoa(iph->ip_src));
		printf("Dst Address: %s\n", inet_ntoa(iph->ip_dst));

	//If it has TCP
	//Print TCP Info
		if (iph -> ip_p == IPPROTO_TCP)
		{
			printf("\nTCP INFO\n");
			tcph = (struct tcp *)(packet + iph ->ip_hl * 4);
			printf("Src Port : %d\n", ntohs(tcph->source));
			printf("Dst Port : %d\n", ntohs(tcph->dest));
		}
		
		printf("Payload Data(Max 16byte): \n");
		for(int i=0; i<16; i++){
			printf("%02x", *(packet++));
		}
	}
	//IF It is not a IP Packet
	else{
		printf("This is not a IP Packet");
	}
	printf("\n---------------------------------------\n\n");
}


int main(int argc, char *argv[]){
	char *dev  = argv[1];
	printf("Device: %s\n", dev);
	
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}

	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	//packet = pcap_next(handle, &header);
	//printf("Jacked a packet with length of [%d]\n", header.len);
	pcap_loop(handle, 0, callback, NULL);

	return(0);
}
