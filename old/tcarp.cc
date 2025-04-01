#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include "tcarp-utils.h"

int debug=0;

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


/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

int main(int argc, char *argv[])
{
	struct pcap_file_header pfh;
	char *filename;
	bool byteswap = false;

	/* start with something like this (or use this if you like it) */
	/* i'm using it */
	if (argc == 2) {
		filename = argv[1];
	} else if ((argc == 3) && (strcmp(argv[1],"-d") == 0)) {
		debug = 1;
		filename = argv[2];
	}
	else if ((argc == 3) && (strcmp(argv[1],"-n") == 0)) {
		filename = argv[2];
	} else {
		fprintf(stdout,"Usage: %s [-d] filename\n", argv[0]);
		exit(99); // a little extreme but i'll allow it
	}

	if (debug) printf("Trying to read from file '%s'\n", filename);

	/* now open the file (or if the filename is "-" make it read from standard input)*/
	int fd = 0; // initiate to 0 as stdin file descriptor (if not stdin then it will be changed)
	if(strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDONLY);
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


	printf("header magic: %08x\n", pfh.magic);
	printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
	printf("header linktype: %d\n\n", pfh.linktype);

	/* now read each packet in the file */
	while (1) {
		char packet_buffer[100000]; // bad boo go away unsafe booos
		
		/* read the pcap_packet_header, then print as requested */
		struct pcap_pkthdr pph;
		ret = read(fd, &pph, sizeof(pph));
		if (byteswap) { // this took me too long to figure this out
			pph.ts_secs = htonl(pph.ts_secs);
			pph.ts_usecs = htonl(pph.ts_usecs);
			pph.caplen = htonl(pph.caplen);
			pph.len = htonl(pph.len);
		}
		
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


		printf("%10d", pph.ts_secs); // i hate cout
		printf(".%06d000\t", pph.ts_usecs);
		printf("%d\t%d\t", pph.caplen, pph.len);
		

		// if (0) // doesn't work yet
		if (pfh.linktype == 1) {
			eth_hdr *eh = (eth_hdr *) packet_buffer;
			print_ethernet(eh);
			if(debug) 
				printf("ethernet type: 0x%04x\n", ntohs(eh->type));

			switch (ntohs(eh->type))
			{
			case 0x0800: // IPv4
				print_IPv4((IPv4 *)(packet_buffer + sizeof(eth_hdr))); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the IPv4 header
				break;
			case 0x0806: // ARP
				print_Arp((ARP *)(packet_buffer + sizeof(eth_hdr))); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the ARP header
				break;
			default:
				break;
			}
		}
		// break;   // to prevent infinite loop until you fix logic
	}
}

