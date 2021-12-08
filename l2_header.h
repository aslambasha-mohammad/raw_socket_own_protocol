#include <stdio.h>		//sscanf
#include <stdlib.h>		//malloc, calloc etc;
#include <string.h>		//strcpy etc;
#include <unistd.h>		//close()
#include <sys/socket.h>		//socket
#include <sys/types.h>
#include <sys/ioctl.h>		//ioctl
#include <net/if.h>		//if_nametoindex
#include <linux/if_ether.h>	//struct ethhdr, ETH_ALEN
#include <linux/filter.h>	//struct sock_filter
#include <linux/if_packet.h>	//struct sockaddr_ll
#include <arpa/inet.h>		//if_nametoindex


#define ETH_MY_PROTO		1234

//tcpdump -i enp1s0 -e ether[12] = 0x12 and ether[13] = 0x34 -dd
struct sock_filter my_l2Msg_filter[] = {
	{ 0x30, 0, 0, 0x0000000c },
	{ 0x15, 0, 3, 0x00000012 },
	{ 0x30, 0, 0, 0x0000000d },
	{ 0x15, 0, 1, 0x00000034 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

enum my_msgType {
	HELLO_MSG = 1,
	BYE_MSG,
};

enum my_tlvYype {
	HELLO_INFO = 1,
	BYE_INFO,
};

struct __attribute__((__packed__)) tlv {
	unsigned char	tlv_type;
	unsigned int	len;
};

struct __attribute__((__packed__)) my_l2_hdr {
	unsigned char	destMac[ETH_ALEN];
	unsigned char	srcMac[ETH_ALEN];
	unsigned short	hdrLen;
	unsigned char	msgType;
	unsigned int	payloadLen;
};

//Macros
#define	MAX_BUFF_LEN		256
#define	ETH_HDR_LEN		sizeof(struct ethhdr)
#define	L2_HDR_LEN		sizeof(struct my_l2_hdr)
#define MAX_MSG_SIZE		(sizeof(struct tlv) + MAX_BUFF_LEN)

// Global variables
unsigned char bcastMac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char nillMac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
