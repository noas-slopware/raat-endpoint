// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * r26cap: minimal packet capture for a box without tcpdump.
 * usage: r26cap <ifname> <peer-ipv4> <seconds> <out.pcap>
 * Captures IPv4 TCP packets to/from <peer> on <ifname> (AF_PACKET, read-only
 * listener: never transmits) and writes a classic pcap file.
 */
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct pcap_hdr { uint32_t magic; uint16_t vmaj, vmin; int32_t tz; uint32_t sig, snap, link; };
struct pcap_rec { uint32_t sec, usec, incl, orig; };

int main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage: r26cap <if> <peer> <seconds> <out.pcap>\n");
		return 2;
	}
	struct in_addr peer;
	if (!inet_aton(argv[2], &peer))
		return fprintf(stderr, "bad peer\n"), 2;
	int secs = atoi(argv[3]);
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));	/* ALL: also our own TX */
	if (s < 0)
		return perror("socket"), 1;
	struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL),
				   .sll_ifindex = if_nametoindex(argv[1]) };
	if (!sll.sll_ifindex || bind(s, (struct sockaddr *)&sll, sizeof(sll)))
		return perror("bind"), 1;
	struct timeval tv = { .tv_sec = 1 };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	FILE *o = fopen(argv[4], "wb");
	if (!o)
		return perror("open"), 1;
	struct pcap_hdr h = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1 /* ethernet */ };
	fwrite(&h, sizeof(h), 1, o);

	unsigned char buf[65536];
	time_t end = time(NULL) + secs;
	unsigned long n = 0, bytes = 0;
	while (time(NULL) < end) {
		ssize_t len = recv(s, buf, sizeof(buf), 0);
		if (len < 14 + 20)
			continue;
		if (buf[12] != 0x08 || buf[13] != 0x00)	/* IPv4 only */
			continue;
		unsigned char *ip = buf + 14;
		if ((ip[0] >> 4) != 4 || ip[9] != 6 /* TCP */)
			continue;
		uint32_t src, dst;
		memcpy(&src, ip + 12, 4);
		memcpy(&dst, ip + 16, 4);
		if (src != peer.s_addr && dst != peer.s_addr)
			continue;
		struct timeval now;
		gettimeofday(&now, NULL);
		struct pcap_rec r = { now.tv_sec, now.tv_usec, len, len };
		fwrite(&r, sizeof(r), 1, o);
		fwrite(buf, len, 1, o);
		n++;
		bytes += len;
	}
	fclose(o);
	fprintf(stderr, "r26cap: %lu packets, %lu bytes\n", n, bytes);
	return 0;
}
