#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <asm/byteorder.h>

typedef unsigned short __u16;
typedef unsigned char __u8;

struct l2tphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 flag_priority : 1,
		flag_offset : 1,
		x3 : 1,
		flag_sequence : 1,
		x2 : 1,
		x1 : 1,
		flag_length : 1,
		flag_type : 1;
	__u8 Ver : 4,
		x4 : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 flag_type : 1,
		flag_length : 1, : 2,
		flag_sequence : 1, : 1,
		flag_offset : 1,
		flag_priority : 1;
	__u8 : 4,
		Ver : 4;
#endif
};

const __u16 l2tp_getlen(const struct l2tphdr *header)
{
	if (!header->flag_length)
	{
		return 0;
	}
	__u16 *offset = (__u16 *)(header + 1);
	return ntohs(*offset);
}

const __u16 l2tp_gettid(const struct l2tphdr *header)
{
	__u16 *tid_offset = (__u16 *)(header + 1);
	if (header->flag_length)
	{
		tid_offset = tid_offset + 1;
	}
	return ntohs(*tid_offset);
}

const __u16 l2tp_getsid(const struct l2tphdr *header)
{
	__u16 *tid_offset = (__u16 *)(header + 1);
	if (header->flag_length)
	{
		tid_offset = tid_offset + 1;
	}
	__u16 *sid_offset = tid_offset + 1;
	return ntohs(*sid_offset);
}

const __u16 l2tp_getNs(const struct l2tphdr *header)
{
	if (!header->flag_sequence)
	{
		return 0;
	}
	__u16 *tid_offset = (__u16 *)(header + 1);
	if (header->flag_length)
	{
		tid_offset = tid_offset + 1;
	}

	__u16 *Ns_offset = tid_offset + 2;
	return ntohs(*Ns_offset);
}

const __u16 l2tp_getNr(const struct l2tphdr *header)
{
	if (!header->flag_sequence)
	{
		return 0;
	}
	__u16 *tid_offset = (__u16 *)(header + 1);
	if (header->flag_length)
	{
		tid_offset = tid_offset + 1;
	}

	__u16 *Nr_offset = tid_offset + 3;
	return ntohs(*Nr_offset);
}

const __u16 l2tp_getofst(const struct l2tphdr *header)
{
	if (!header->flag_offset)
	{
		return 0;
	}
	__u16 *tid_offset = (__u16 *)(header + 1);
	if (header->flag_length)
	{
		tid_offset = tid_offset + 1;
	}
	__u16 *ofst_offset = tid_offset + 2;
	if (header->flag_sequence)
	{
		ofst_offset = ofst_offset + 2;
	}
	return ntohs(*ofst_offset);
}

const int l2tp_gethdrlen(const struct l2tphdr *header)
{
	if (header->flag_offset)
	{
		return l2tp_getofst(header);
	}
	else
	{
		int offset = 2 +
					 (header->flag_length ? 2 : 0) + 4 +
					 (header->flag_sequence ? 4 : 0);
		return offset;
	}
}

void packet_handler(
	u_char *,
	const struct pcap_pkthdr *,
	const u_char *);
void replace(pcap_t *);
void print_l2tp(const l2tphdr *, int);

int main(int argc, char **argv)
{
	char device[] = "ens33";
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int ret;
	/* Snapshot length is how many bytes to capture from each packet. This includes*/
	int snapshot_length = 1024;
	/* End the loop after this many packets are captured */
	int total_packet_count = 10;
	int argument[2] = {0, 0};
	bool r = 0;
	u_char *my_arguments = (u_char *)(argument);
	char filter_exp[] = "udp port 1701";
	char *myfilter = filter_exp;
	struct bpf_program filter;
	bpf_u_int32 mask, net;

	for (int i = 0; i < argc; i++)
	{
		char *str = argv[i];
		if (str[0] == '-')
		{
			if (strlen(str) == 1)
			{
				printf("Unknown arguments\n");
				exit(1);
			}
			if ('n' == str[1])
			{
				if (i + 1 >= argc)
				{
					printf("too few arguments\n");
					exit(1);
				}
				total_packet_count = atoi(argv[i + 1]);
			}
			if ('d' == str[1])
			{
				if (i + 1 >= argc)
				{
					printf("too few arguments\n");
					exit(1);
				}
				char *host_ip = argv[i + 1];
				strncat(myfilter, " and dst host ", 100);
				strncat(myfilter, host_ip, 100);
				printf("Filter is: %s\n", myfilter);
			}
			if ('s' == str[1])
			{
				if (i + 1 >= argc)
				{
					printf("too few arguments\n");
					exit(1);
				}
				char *host_ip = argv[i + 1];
				strncat(myfilter, " and src host ", 100);
				strncat(myfilter, host_ip, 100);
				printf("Filter is: %s\n", myfilter);
			}
			if ('c' == str[1])
			{
				r = 1;
			}
		}
	}

	if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1)
	{
		printf("Could not get netmask for device %s: %s\n", device, error_buffer);
		exit(1);
	}

	if (NULL == (handle = pcap_create(device, error_buffer)))
	{
		printf("Error getting the handle: %s\n", error_buffer);
		exit(1);
	}

	if (0 > (ret = pcap_activate(handle)))
	{
		printf("Error activating\n");
		exit(1);
	}

	if (-1 == pcap_compile(handle, &filter, filter_exp, 0, net))
	{
		printf("Could not parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	if (1 == r)
	{
		replace(handle);
		return 0;
	}

	if (-1 == pcap_setfilter(handle, &filter))
	{
		printf("Could not set filter '%s': %s", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	// handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
	pcap_loop(handle, total_packet_count, packet_handler, my_arguments);
	printf("Total packets length is: %d\n", argument[0]);

	return 0;
}

void print_l2tp(const l2tphdr *l2tp_header, int l2tp_length)
{
	const u_char *payload;
	if (0x02 == l2tp_header->Ver)
	{
		printf("L2TP packet\n");
		printf("Version: L2TP 2\n");
	}
	else
	{
		printf("version error: version is %d\n", l2tp_header->Ver);
		exit(1);
	}
	if (l2tp_header->flag_type)
	{
		printf("Type: control message\n");
	}
	else
	{
		printf("Type: data message\n");
	}
	int tid = l2tp_gettid(l2tp_header);
	int sid = l2tp_getsid(l2tp_header);
	printf("Tunnel id: %d\n", tid);
	printf("Session id: %d\n", sid);

	if (l2tp_header->flag_sequence)
	{
		int Ns = l2tp_getNs(l2tp_header);
		int Nr = l2tp_getNr(l2tp_header);
		printf("Sequence number:\n");
		printf("\tNs: %d\n", Ns);
		printf("\tNr: %d\n", Nr);
	}
	else
	{
		printf("Sequence number: not given\n");
	}

	int priority = l2tp_header->flag_priority;
	printf("Priority of the message: %d\n", priority);

	int offset = l2tp_getofst(l2tp_header);
	if (l2tp_header->flag_offset)
	{
		printf("Offset of the payload: %d\n", offset);
	}
	else
	{
		printf("Offset of the payload: not given\n");
	}

	int l2tp_header_length = l2tp_gethdrlen(l2tp_header);
	printf("Payload offset: %d\n", l2tp_header_length);
	int payload_length = l2tp_length - l2tp_header_length;
	// int payload_length = header->caplen -
	//  (ethernet_header_length + ip_header_length + udp_header_length + l2tp_header_length);
	payload = ((const u_char *)l2tp_header) + l2tp_header_length;
	printf("Payload:\n");
	int bytecounts = 0;
	printf("   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
	while (bytecounts < payload_length)
	{
		if (bytecounts % 16 == 0)
		{
			int row = bytecounts / 16;
			printf("%02X ", row);
		}
		int cur = *(payload + bytecounts);
		printf("%02X ", cur);
		if (bytecounts % 16 == 15)
		{
			printf("\n");
		}
		bytecounts = bytecounts + 1;
	}
	printf("--END--\n\n\n");
}

void replace(pcap_t *handle)
{
	struct pcap_pkthdr header;
	const u_char *packet;
	/* capture a packet */
	packet = pcap_next(handle, &header);
	if (NULL == packet)
	{
		printf("No packet found\n");
		exit(1);
	}
	/* analyze the packet header */
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
	{
		printf("Not an IP packet. Skipping...\n\n");
		return;
	}
	/* Pointers to start point of headers */
	const u_char *ip_header;
	const u_char *udp_header;
	const l2tphdr *l2tp_header;
	/* Header lengths */
	int packet_length = header.caplen;
	int ethernet_header_length = 14;
	int ip_header_length;
	int udp_header_length = 8;
	int l2tp_header_length;
	int payload_length;
	/* start of IP header */
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((iphdr *)ip_header)->ihl;
	ip_header_length = ip_header_length * 4;
	/* make sure it is UDP */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_UDP)
	{
		printf("Not a UDP packet. Skipping...\n\n");
		return;
	}
	/* start of UDP header */
	udp_header = ip_header + ip_header_length;
	/* start of L2TP header */
	l2tp_header = (const l2tphdr *)(udp_header + udp_header_length);
	if (0x02 == l2tp_header->Ver)
	{
		printf("L2TP packet\n");
		printf("Version: L2TP 2\n");
	}
	else
	{
		printf("version error: version is %d\n", l2tp_header->Ver);
		exit(1);
	}
	int tid = l2tp_gettid(l2tp_header);
	int sid = l2tp_getsid(l2tp_header);
	printf("Tunnel id: %d\n", tid);
	printf("Session id: %d\n", sid);
	/* new packet */
	l2tp_header_length = l2tp_gethdrlen(l2tp_header);
	int header_length = ethernet_header_length + ip_header_length + udp_header_length + l2tp_header_length;
	payload_length = packet_length - header_length;

	u_char *new_packet = (u_char *)malloc(packet_length);
	memcpy(new_packet, packet, header_length);
	u_char *new_payload = (u_char *)malloc(payload_length);
	memset(new_payload, 0, payload_length);
	memcpy(new_payload, "1953246ruoy", payload_length);
	memcpy(new_packet + header_length, new_payload, payload_length);

	pcap_sendpacket(handle, new_packet, packet_length);

	free(new_payload);
	free(new_packet);
	printf("Payload change Success\n\n");
}

void packet_handler(
	u_char *args,
	const struct pcap_pkthdr *header,
	const u_char *packet)
{
	/* make sure we have an IP packet */
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
	{
		printf("Not an IP packet. Skipping...\n\n");
		return;
	}

	printf("--START--\n");
	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);
	int *pointer = (int *)args;
	pointer[0] = pointer[0] + header->caplen;

	/* Pointers to start point of headers */
	const u_char *ip_header;
	const u_char *udp_header;
	const l2tphdr *l2tp_header;

	/* Header lengths */
	int ethernet_header_length = 14;
	int ip_header_length;
	int udp_header_length = 8;
	int l2tp_length;

	/* start of IP header */
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((iphdr *)ip_header)->ihl;
	ip_header_length = ip_header_length * 4;
	printf("IP header length: %d\n", ip_header_length);

	/* make sure it is UDP */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_UDP)
	{
		printf("Not a UDP packet. Skipping...\n\n");
		return;
	}

	/* start of UDP header */
	udp_header = ip_header + ip_header_length;
	/* start of L2TP header */
	l2tp_header = (const l2tphdr *)(udp_header + udp_header_length);
	l2tp_length = header->caplen -
				  ethernet_header_length - ip_header_length - udp_header_length;
	print_l2tp(l2tp_header, l2tp_length);
}