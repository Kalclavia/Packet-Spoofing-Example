#include "common.h"

int main()
{
    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    ipheader *ip = (ipheader *)buffer;
    udpheader *udp = (udpheader *)(buffer + sizeof(ipheader));

    // add data (Given, do not edit)
    char *data = (char *)udp + sizeof(udpheader);
    int data_len = strlen(CLIENT_IP);
    strncpy(data, CLIENT_IP, data_len);

    // create udp header
    // DONE
    udp->udp_sport = htons(CLIENT_PORT);
    udp->udp_dport = htons(SERVER_PORT);
    udp->udp_ulen = htons(sizeof(*udp) + data_len);

    // create ip header
    // DONE
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr(SPOOF_IP);
    ip->iph_destip.s_addr = inet_addr(SERVER_IP);
    ip->iph_protocol = IPPROTO_UDP; // Sets IP Protocol to UDP, not TCP as we usually used
    ip->iph_len = htons(sizeof(*ip) + sizeof(*udp) + data_len);
    
    // send packet
    // DONE
    send_raw_ip_packet(ip);

    return 0;
}