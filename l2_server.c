#include "l2_header.h"

char intfName[32] = {'\0'};
unsigned char intfMac[ETH_ALEN] = {'\0'};
unsigned char bcastMac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char destMac[ETH_ALEN] = {'\0'};
unsigned char nillMac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int send_l2Msg(int sockId, char *buff, enum my_msgType msgType)
{
	struct sockaddr_ll 	sadd_ll;
	char *pkt	= NULL;
	struct my_l2_hdr *msgHdr = NULL;
	struct ethhdr	*ethHdr	= NULL;
	char *payload	= NULL;
	unsigned int paylaodLen = 0;
	unsigned int hdr_len = 0, total_len = 0;

	hdr_len = (ETH_HDR_LEN + L2_HDR_LEN);
	payloadLen = strlen(buff);
	total_len = (hdr_len + payloadLen);

	pkt = (char *)calloc(sizeof(char), total_len);
	if(pkt == NULL)
	{
		printf("Failed to allocate memory for a packet\n");
		return -1;
	}

	ethHdr = (struct ethhdr *)pkt;
	msgHdr = (struct my_l2_hdr *)(pkt + ETH_HDR_LEN);
	payload = (pkt + hdr_len);

	memset(&saddr_ll, '\0', sizeof(saddr_ll));
	memcpy(ethHdr->h_source, intfMac, ETH_ALEN);
	if(strcmp(destMac, nillMac) == 0)
	{
		memcpy(ethHdr->h_dest, bcastMac, ETH_ALEN);
		memcpy(saddr_ll.sll_addr, bcastMac, ETH_ALEN);
		memcpy(msgHdr->destMac, bcastMac, ETH_ALEN);
	}
	else
	{
		memcpy(ethHdr->h_dest, destMac, ETH_ALEN);
		memcpy(saddr_ll.sll_addr, destMac, ETH_ALEN);
		memcpy(msgHdr->destMac, destMac, ETH_ALEN);
	}
	ethHdr->h_proto = htons(ETH_MY_PROTO);
	
	memcpy(msgHdr->srcMac, intfMac, ETH_ALEN);
	msgHdr->hdrLen = htons(L2_HDR_LEN);
	msgHdr->msgType = (unsigned char) msgType;
	msgHdr->payloadLen = htonl(payloadLen);

	memcpy(paylaod, buff, paylaodLen);

}

int recv_l2Msg(int sockId, char *buff)
{
}

int get_ifMacAddr(int sockId, const char *intfName, unsigned char *mac)
{
	struct ifreq ifr;

	memset(&ifr, '\0', sizeof(ifr));
	strncpy(&ifr.ifr_name, intfName, strlen(intfName));
	ifr.ifr_ifindex = if_nametoindex(intfName);

	if(ioctl(sockId, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Unable to get the '%s' Mac address\n", intfName);
		return -1;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

int main(int argc, char **argv)
{
	if(argc != 2 || argc != 3)
	{
		printf("Usage: %s <interface name> [destnation mac if known]\n", agrv[0]);
		return -1;
	}

	int sock_Id = 0;
	struct sockaddr_ll sock_addr;
	struct sock_fprog bpf;
	char msgBuff[256] = {'\0'};
	unsigned char dstMac[ETH_ALEN] = {'\0'};

	//Creating the unnamed Raw socket
	sock_Id = socket(PF_PACKET, SOCK_RAW, htons(ETH_MY_PROTO));
	if(sock_Id < 0)
	{
		printf("Failed to create a Raw socket\n");
		return -1;
	}

	//Binding the socket to the interface index
	memset(&sock_addr, '\0', sizeof(sock_addr));
	sock_addr.sll_family = AF_PACKET;
	sock_addr.sll_ifindex = ifnametoindex(intfName);
	if(bind(sock_Id, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
	{
		printf("Unable to bind the raw socket to interface: %s\n", intfName);
		close(sock_Id);
		return -1;
	}

	//Setting socket option to filter only My own L2 protocol Msgs
	bpf.len = (sizeof(struct my_l2Msg_filter)/sizeof(struct my_l2Msg_filter[0]));
	bpf.filter = my_l2Msg_filter;
	if(setsockopt(sock_Id, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
	{
		printf("Unable to set the socket option to filter own L2 msgs\n");
		close(sock_Id);
		return -1;
	}

	strcpy(intfName, argv[1]);
	if(argc == 3)
	{
		//converting the string MAC given to actual unsigned char Mac format
		sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &dstMac[0], &dstMac[1], &dstMac[2], &dstMac[3], &dstMac[4], &dstMac[5]);
		destMac[0] = (unsigned char) dstMac[0];
		destMac[1] = (unsigned char) dstMac[1];
		destMac[2] = (unsigned char) dstMac[2];
		destMac[3] = (unsigned char) dstMac[3];
		destMac[4] = (unsigned char) dstMac[4];
		destMac[5] = (unsigned char) dstMac[5];
	}

        if(get_ifMacAddr(sock_Id, intfName, intfMac) != 0)
        {
                printf("Unable to get MAC or Invalid interface name provided\n");
		close(sock_Id);
                return -1;
        }

	//send a sample L2 msg to other host/device
	strcpy(msgBuff, "Hello l2_client");
	if(send_l2Msg(sock_Id, msgBuff, HELLO_MSG) != 0)
	{
		printf("Failed to send Hello msg to client\n");
	}

	memset(msgBuff, '\0', sizeof(msgBuff));
	if(recv_l2Msg(sock_Id, msgBuff) != 0)
	{
		printf("Failed to receive the msg from client\n");
	}

	close(sock_Id);
	return 0;
}
