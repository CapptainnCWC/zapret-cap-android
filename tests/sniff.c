// Shows outgoing packets on the device: ttl, seq, first bytes. tcpdump isn't there on Android images.
//   sniff IFACE SECONDS [PORT]      needs root
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (sock < 0) { perror("socket"); return 1; }
	struct sockaddr_ll sa = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = if_nametoindex(argv[1])};
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
	int port = argc > 3 ? atoi(argv[3]) : 0;
	time_t end = time(0) + atoi(argv[2]);
	unsigned char b[65536];
	unsigned base = 0;
	puts("ready");
	fflush(stdout);
	while (time(0) < end) {
		struct pollfd p = {.fd = sock, .events = POLLIN};
		if (poll(&p, 1, 200) <= 0) continue;
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(sock, b, sizeof(b), 0, (struct sockaddr *)&from, &fl);
		if (n < 28 || from.sll_pkttype != PACKET_OUTGOING || (b[0] >> 4) != 4) continue;
		int ihl = (b[0] & 15) * 4, proto = b[9], ttl = b[8];
		unsigned char *l4 = b + ihl;
		int sport = l4[0] << 8 | l4[1], dport = l4[2] << 8 | l4[3];
		if (port && dport != port) continue;
		char dst[32];
		inet_ntop(AF_INET, b + 16, dst, sizeof(dst));
		if (proto == 17) {
			int len = (l4[4] << 8 | l4[5]) - 8;
			printf("udp %s:%d ttl=%d len=%d ", dst, dport, ttl, len);
			for (int i = 0; i < 10 && i < len; i++) printf("%02x", l4[8 + i]);
			puts("");
		} else if (proto == 6) {
			unsigned seq = (unsigned)l4[4] << 24 | l4[5] << 16 | l4[6] << 8 | l4[7];
			int hlen = (l4[12] >> 4) * 4, flags = l4[13];
			int total = b[2] << 8 | b[3];
			int len = total - ihl - hlen;
			if (flags & 2) base = seq;
			printf("tcp %s:%d ttl=%-3d %c%c%c%c rel=%-6u len=%-5d ", dst, dport, ttl,
				flags & 2 ? 'S' : '.', flags & 8 ? 'P' : '.', flags & 16 ? 'A' : '.', flags & 1 ? 'F' : '.', seq - base, len);
			for (int i = 0; i < 12 && i < len; i++) printf("%02x", l4[hlen + i]);
			puts("");
		}
		fflush(stdout);
	}
	return 0;
}
