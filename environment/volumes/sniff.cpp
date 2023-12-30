#include <stdio.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ctype.h>

#include "common.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "udp";
	bpf_u_int32 net;

	// Step 1: Open live PCAP session handle on NIC using your interface name
	// DONE

	std::string interface_id = "br-d756c77fd5e1";	// I used ifconfig to find the first interface, and used this interface name for the pcap. This worked so I'm sticking to it
	handle = pcap_open_live(interface_id.c_str(), BUFSIZ, 1, 1000, errbuf);	
	if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", interface_id.c_str(), errbuf);
    	return(2);
	}

	// Step 2: Compile filter_exp into BPF pseudo-code
	// DONE

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Error! Couldn't parse the filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Error! Couldn't install the filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}


	// Step 3: Capture packets
	printf("Sniffing...\n");
	// DONE
	pcap_loop(handle, -1, got_packet, NULL);

	// Close the PCAP session handle
	// DONE
	pcap_close(handle);

	return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	struct ethheader *eth = (struct ethheader *)packet;

	if (ntohs(eth->ether_type) == 0x800)
	{
		printf("\nReceived packet\n");
		struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
		printf("	From:%s\n", inet_ntoa(ip->iph_sourceip));
		printf("	To:%s\n", inet_ntoa(ip->iph_destip));

		char *data = (char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct udpheader);
		int size_data = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct udpheader));
		if (size_data > 0)
		{
			printf("   Payload (%d bytes):\n", size_data);
			for (int i = 0; i < size_data; i++)
			{
				if (isprint(*data))
					printf("%c", *data);
				else
					printf(".");
				data++;
			}
		}
	}
	return;
}
