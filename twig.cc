#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include "twig-utils.h"

// Global vars

int debug = 0;
int twig_debug = 0;
int fd = 0; // initiate to 0 as stdin file descriptor (if not stdin then it will be changed)

bool byteswap = false;


// Debug function declarations  

void print_ethernet(struct eth_hdr *peh);

void print_UDP(UDP *udp);

void print_TCP(TCP *tcp);

void print_IPv4(IPv4 *ipv4);

void print_Arp(ARP *arp);

void print_ICMP(ICMP *icmp);


// Actual function declaration
void do_ICMP(pcap_pkthdr phead, eth_hdr *ehead, IPv4 *ip, ICMP *icmp);

u_short ICMP_checksum_maker(u_short *buffer, int size);

u_short IPv4_checksum_maker(u_short *buffer, int size);

void build_and_send(pcap_pkthdr phead, eth_hdr *ehead, IPv4 *ip, ICMP *icmp, int size);


/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

int main(int argc, char *argv[])
{
	struct pcap_file_header pfh;
	char *filename;

	/* start with something like this (or use this if you like it) */
	/* i'm using it */
	if (argc == 2) {
		filename = argv[1];
	} else if ((argc == 3) && (strcmp(argv[1],"-d") == 0)) {
		debug = 1;
		twig_debug = 1;
		filename = argv[2];
	}
	else if ((argc == 3) && (strcmp(argv[1],"-n") == 0)) {
		filename = argv[2];
	} 
    else if ((argc == 3) && (strcmp(argv[1],"-td") == 0)) {
        twig_debug = 1;
		filename = argv[2];
	} else {
		fprintf(stdout,"Usage: %s [-d,-td] filename\n", argv[0]);
		exit(99); // a little extreme but i'll allow it
	}

	if (debug) printf("Trying to read from file '%s'\n", filename);

	/* now open the file (or if the filename is "-" make it read from standard input)*/
	if(strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDWR);
		// fd = open(filename, O_RDWR | O_APPEND);
		if(debug) printf("fd: %d\n", fd);
		if (fd < 0) {
			if(debug) printf("fd: %d < 0\n", fd);
			fprintf(stderr, "%s: Permission denied\n", filename); // Doesn't hit on Windows but does on Linux
			exit(1);
		}
	} 


	/* read the pcap_file_header at the beginning of the file, check it, then print as requested */
	int ret = 0;
	ret = read(fd, &pfh, sizeof(pfh));
	if(ret != sizeof(pfh)) {
		fprintf(stderr, "truncated pcap header: only %d bytes\n", ret);
		exit(1);
	}
	if (pfh.magic != PCAP_MAGIC) 
	{
		if(htonl(pfh.magic) == PCAP_MAGIC)
		{
			if(debug)
				printf("byte order reversed\n");
			pfh.magic = htonl(pfh.magic);
			pfh.version_major = ntohs(pfh.version_major);
			pfh.version_minor = ntohs(pfh.version_minor);
			pfh.linktype = htonl(pfh.linktype);

			// these aren't used, but i did it just in case
			pfh.thiszone = htonl(pfh.thiszone);
			pfh.sigfigs = htonl(pfh.sigfigs);
			pfh.snaplen = htonl(pfh.snaplen);
			byteswap = true;

			if(debug || twig_debug)
				printf("byte order reversed\n");
			
		}
		else
		{
			fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
			exit(1);
		}
	}

	if(pfh.version_major != PCAP_VERSION_MAJOR || pfh.version_minor != PCAP_VERSION_MINOR)
	{
		fprintf(stderr, "invalid pcap version: %d.%d\n", pfh.version_major, pfh.version_minor);
		exit(1);
	}


    if(debug) {
        printf("header magic: %08x\n", pfh.magic);
        printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
        printf("header linktype: %d\n\n", pfh.linktype);
    }

	/* now read each packet in the file */
	while (1) {
		char packet_buffer[100000]; // bad boo go away unsafe booos
		
		/* read the pcap_packet_header, then print as requested */
		struct pcap_pkthdr pph;
		ret = read(fd, &pph, sizeof(pph));
		
		if(debug) 
		{
			printf("Packet header read %d bytes\n", ret);
			printf("Read: ");
			for (int i = 0; i < ret; i++) {
				printf("%02d ", ((unsigned char *)&pph)[i]);
			}
			printf("\n");
			fflush(stdout);
		}
		
		if (ret == 0) {
			break;
		}
		
		if(ret != sizeof(pph)) {
			fprintf(stderr, "truncated packet header: only %d bytes\n", ret);
			break;
		}
		
		if (byteswap) { // this took me too long to figure this out
			pph.ts_secs = htonl(pph.ts_secs);
			pph.ts_usecs = htonl(pph.ts_usecs);
			pph.caplen = htonl(pph.caplen);
			pph.len = htonl(pph.len);
		}
		
		/* then read the packet data that goes with it into a buffer (variable size) */
		// pph.caplen = htonl(pph.caplen);

		fflush(stdout);
		ret = read(fd, packet_buffer, pph.caplen);
		
		if(debug) 
		{
			printf("Packet read %d bytes\n", ret);
			fflush(stdout);
			printf("Read: ");
			for (int i = 0; i < ret; i++) {
				printf("%02d ", ((unsigned char *)&pph)[i]);
			}
			printf("\n");
		}
		
		if (ret < static_cast<int>(pph.caplen)) {
			fprintf(stderr, "truncated packet: only %d bytes\n", ret);
			exit(1);
		}

        if(debug) {
            printf("%10d", pph.ts_secs); // i hate cout
            printf(".%06d000\t", pph.ts_usecs);
            printf("%d\t%d\t", pph.caplen, pph.len);
        }
		

		if (pfh.linktype == 1) {
			eth_hdr *eh = (eth_hdr *) packet_buffer;
            if(debug) print_ethernet(eh);
			if(debug) 
				printf("ethernet type: 0x%04x\n", ntohs(eh->type));

			switch (ntohs(eh->type))
			{
			case 0x0800: // IPv4
            {
                IPv4 *ip_head = (IPv4 *)(packet_buffer + sizeof(eth_hdr));
				if(debug) print_IPv4(ip_head); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the IPv4 header
                if(ip_head->type == 1) 
                {
					ICMP *icmp = (ICMP *)(packet_buffer + sizeof(eth_hdr) + sizeof(IPv4));
                    if(twig_debug)
					{
						printf("### We got ourselves an ICMP header ###\n");
						print_ethernet(eh);
						print_IPv4(ip_head);
						print_ICMP(icmp);
					}
                    do_ICMP(pph, eh, ip_head, icmp);
                }
				break;
            }
			case 0x0806: // ARP
				if(debug) print_Arp((ARP *)(packet_buffer + sizeof(eth_hdr))); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the ARP header
				break;
			default:
				break;
			}
		}
		usleep(100000); // Delay
	}
}


/* Function definitions */ 

void print_ethernet(struct eth_hdr *peh) {
	// Had to swap to printf because cout was breaking the output for some reason
	printf("%02x:%02x:%02x:%02x:%02x:%02x\t", peh->dest[0], peh->dest[1], peh->dest[2], peh->dest[3], peh->dest[4], peh->dest[5]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\t", peh->src[0], peh->src[1], peh->src[2], peh->src[3], peh->src[4], peh->src[5]);
	printf("0x%04x\n", ntohs(peh->type));
	fflush(stdout);
}

void print_UDP(UDP *udp) {
	printf("\tUDP:\tSport:\t%d\n", ntohs(udp->sport));
	printf("\t\tDport:\t%d\n", ntohs(udp->dport));
	printf("\t\tDGlen:\t%d\n", ntohs(udp->len));
	printf("\t\tCSum:\t%d\n", ntohs(udp->csum));
}

void print_TCP(TCP *tcp) {
	printf("\tTCP:\tSport:\t%d\n", ntohs(tcp->sport));
	printf("\t\tDport:\t%d\n", ntohs(tcp->dport));

	printf("\t\tFlags:\t%s", (tcp->flags & 0x01 ? "F" : "-"));
	printf("%s", (tcp->flags & 0x02 ? "S" : "-"));
	printf("%s", (tcp->flags & 0x04 ? "R" : "-"));
	printf("%s", (tcp->flags & 0x08 ? "P" : "-"));
	printf("%s", (tcp->flags & 0x10 ? "A" : "-"));
	printf("%s", (tcp->flags & 0x20 ? "U" : "-"));
	printf("\n");

	printf("\t\tSeq:\t%u\n", ntohl(tcp->seq));
	printf("\t\tACK:\t%u\n", ntohl(tcp->ack));
	printf("\t\tWin:\t%d\n", ntohs(tcp->win));
	printf("\t\tCSum:\t%d\n", ntohs(tcp->csum));
}

void print_IPv4(IPv4 *ipv4) {
	printf("\tIP:\tVers:\t4\n");
	printf("\t\tHlen:\t%d bytes\n", (ipv4->hlen & 0x0F) * 4); // this was also gross
	printf("\t\tSrc:\t%d.%d.%d.%d\t\n", ipv4->src[0], ipv4->src[1], ipv4->src[2], ipv4->src[3]);
	printf("\t\tDest:\t%d.%d.%d.%d\t\n", ipv4->dest[0], ipv4->dest[1], ipv4->dest[2], ipv4->dest[3]);
	printf("\t\tTTL:\t%d\n", ipv4->ttl);
	printf("\t\tFrag Ident:\t%d\n", ntohs(ipv4->frag_ident));
	
	printf("\t\tFrag Offset:\t%d\n", (ntohs(ipv4->frag_offset) & 0x1FFF) * 8); // this was gross; i had to look up the offset for the offset

	printf("\t\tFrag DF:\t%s\n", (ntohs(ipv4->frag_offset) & 0x4000) ? "yes" : "no"); // i haven't had an excuse to use a ? in a while
	printf("\t\tFrag MF:\t%s\n", (ntohs(ipv4->frag_offset) & 0x2000) ? "yes" : "no");
	printf("\t\tIP CSum:\t%d\n", ntohs(ipv4->csum));
	if(ipv4->type == 0x06) {
		printf("\t\tType:\t0x%x\t(TCP)\n", ipv4->type);
		print_TCP((TCP *)(ipv4 + 1));
	} else if(ipv4->type == 0x11) {
		printf("\t\tType:\t0x%x\t(UDP)\n", ipv4->type);
		print_UDP((UDP *)(ipv4 + 1));
	} else
		printf("\t\tType:\t0x%x\t\n", ipv4->type);
}

void print_Arp(ARP *arp) {
	printf("\tARP:\tHWtype:\t%d\n", ntohs(arp->htype));
	printf("\t\thlen:\t%d\n", arp->hlen);
	printf("\t\tplen:\t%d\n", arp->plen);
	printf("\t\tOP:\t%d (ARP %s)\n", ntohs(arp->op), (ntohs(arp->op) == 1) ? "request" : "reply");
	printf("\t\tHardware:\t%02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
	printf("\t\t\t==>\t%02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
	printf("\t\tProtocol:\t%d.%d.%d.%d\t\n", arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
	printf("\t\t\t==>\t%d.%d.%d.%d\t\n", arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
}

void print_ICMP(ICMP *icmp){
    printf("\tICMP:\tType:\t%d\n", icmp->type);
    printf("\t\tCode:\t%d\n", icmp->code);
    printf("\t\tCSum:\t%d\n", ntohs(icmp->checksum));
    if (icmp->type == 0 || icmp->type == 8) { // Echo reply or request
        printf("\t\tID:\t%d\n", ntohs(icmp->id));
        printf("\t\tSeq:\t%d\n", ntohs(icmp->seq));
    }
}

void do_ICMP(pcap_pkthdr phead, eth_hdr *ehead, IPv4 *ip, ICMP *icmp){
	ICMP *reply = (ICMP *)malloc(sizeof(ICMP));
	if (!reply) {
		fprintf(stderr, "Memory allocation failed for ICMP reply\n");
		exit(1);
	}

	// ethernet header
	eth_hdr *eh = (eth_hdr *)malloc(sizeof(eth_hdr));
	if (!eh) {
		fprintf(stderr, "Memory allocation failed for ethernet header\n");
		free(reply);
		exit(1);
	}

	//IPv4 header
	IPv4 *ip_head = (IPv4 *)malloc(sizeof(IPv4));
	if (!ip_head) {
		fprintf(stderr, "Memory allocation failed for IPv4 header\n");
		free(reply);
		free(eh);
		exit(1);
	}

    if(icmp->type == 8) // We got an echo request (ping), we must reply!!! I've been pinged!!!!!!
    {

		// Calculate checksum after setting all fields
		// reply = icmp;
		reply = (ICMP *)memccpy(reply, icmp, sizeof(ICMP), sizeof(ICMP));
        reply->type = 0; // Echo reply
		reply->code = 0; // Code for echo reply
		reply->id = icmp->id; // Copy the ID from the request
		reply->seq = icmp->seq; // Copy the sequence number from the request
		reply->checksum = 0; // Temporary value, will be calculated later
		reply->checksum = ICMP_checksum_maker((u_short *)reply, sizeof(ICMP));

		// Copy the ethernet header and IP headers


		memcpy(eh, ehead, sizeof(eth_hdr));
		memcpy(eh->dest, ehead->src, 6); // Swap source and destination MAC addresses
		memcpy(eh->src, ehead->dest, 6);


		memcpy(ip_head, ip, sizeof(IPv4));
		memcpy(ip_head->dest, ip->src, 4); // Swap source and destination IP addresses
		memcpy(ip_head->src, ip->dest, 4);
		ip_head->len = htons(sizeof(IPv4) + sizeof(ICMP)); // Set the length of the IP header
		ip_head->frag_ident = htons(0); // Set the fragment identifier to 0
		ip_head->frag_offset = htons(0); // Set the fragment offset to 0
		ip_head->ttl = 64; // Set the TTL to 64
		ip_head->csum = 0; // Temporary value, will be calculated later
		ip_head->csum = IPv4_checksum_maker((u_short *)ip_head, sizeof(IPv4));

		if(twig_debug)
		{
			printf("### ICMP Reply ###\n");
			print_ethernet(eh); // Print the ethernet header for debugging
			print_IPv4(ip_head); // Print the IPv4 header for debugging
			print_ICMP(reply); // Print the ICMP header for debugging
		}
    }

	if(twig_debug)
	{
		printf("Attempting to write reply to pcap file\n");
		printf("ICMP Reply:\n");
		print_ICMP(reply);
	}

	build_and_send(phead, ehead, ip_head, reply, sizeof(ICMP));


}

u_short ICMP_checksum_maker(u_short *buffer, int size) {
	unsigned long sum = 0;

	// Sum up 16-bit words
	while (size > 1) {
		sum += *buffer++;
		size -= 2;
	}

	// Add any remaining byte
	if (size == 1) {
		sum += *(u_char *)buffer;
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = ntohs((sum & 0xFFFF) + (sum >> 16));
	}

	return ~sum;
}

u_short IPv4_checksum_maker(u_short *buffer, int size)
{
	unsigned long sum = 0;

	// Sum up 16-bit words
	while (size > 1) {
		sum += *buffer++;
		size -= 2;
	}

	// Add any remaining byte
	if (size == 1) {
		sum += *(u_char *)buffer;
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

void build_and_send(pcap_pkthdr phead, eth_hdr *ehead, IPv4 *ip, ICMP *icmp, int size) {
	// Time to write to pcap file
	pcap_pkthdr pph;
	pph.ts_secs = phead.ts_secs; // Use the original timestamp directly without htons
	pph.ts_usecs = phead.ts_usecs; // Preserve the original microseconds
	pph.caplen = sizeof(eth_hdr) + sizeof(IPv4) + sizeof(ICMP); // Set the captured length
	pph.len = pph.caplen; // Set the actual length to the captured length

	if(twig_debug){
		printf("sizeof(pcap_pkthdr): %zu\n", sizeof(pcap_pkthdr));
		printf("sizeof(eth_hdr): %zu\n", sizeof(eth_hdr));
		printf("sizeof(IPv4): %zu\n", sizeof(IPv4));
		printf("sizeof(ICMP): %zu\n", sizeof(ICMP));
		printf("ICMP type : %d\n", icmp->type);
	}
	
	// Convert headers to network byte order
	// if(byteswap){
	// 	ehead->type = htons(ehead->type); // Ethernet type to network byte order
	// 	ip->len = htons(ntohs(ip->len)); // IPv4 length to network byte order
	// 	ip->frag_ident = htons(ntohs(ip->frag_ident)); // Fragment identifier to network byte order
	// 	ip->frag_offset = htons(ntohs(ip->frag_offset)); // Fragment offset to network byte order
	// 	ip->csum = htons(ntohs(ip->csum)); // IPv4 checksum to network byte order
	// 	icmp->checksum = htons(icmp->checksum); // Ensure checksum is in network byte order
	// }
	
	// Build the packet here
	iovec packet[10]; // Reduce size to 1 as only one element is used
	// pcap packet header, packet header, ethernet header, data
	packet[0].iov_base = (char *)&pph; // pph is the pcap packet header
	packet[0].iov_len = sizeof(pph); // 16 bytes for the iov_len
	packet[1].iov_base = (char *)ehead; // ehead is the ethernet header
	packet[1].iov_len = sizeof(eth_hdr); // 14 bytes for the iov_len
	packet[2].iov_base = (char *)ip; // ip is the IPv4 header
	packet[2].iov_len = sizeof(IPv4); // 20 bytes for the iov_len
	packet[3].iov_base = (icmp);
	packet[3].iov_len = sizeof(ICMP); // 8 bytes for the iov_len
	

	
	// Send the packet here
	if(writev(fd, packet, 4) == -1) // Correct the number of iovec elements to include ICMP
	{
		perror("writev failed");
		free(icmp);
		free(ip);
		free(ehead);
		exit(1);
	}

}
