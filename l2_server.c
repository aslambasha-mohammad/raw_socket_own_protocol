#include "l2_header.h"

char intfName[32] = {'\0'};
unsigned char intfMac[ETH_ALEN] = {'\0'};
unsigned char destMac[ETH_ALEN] = {'\0'};

int send_l2Msg(int sockId, char *buff, enum my_msgType msgType)
{
	struct sockaddr_ll 	saddr_ll;
	char *pkt	= NULL;
	struct my_l2_hdr *msgHdr = NULL;
	struct ethhdr	*ethHdr	= NULL;
	char *payload	= NULL;
	struct tlv	tlv_buff;
	unsigned int payloadLen = 0, send_len = 0;
	unsigned int hdr_len = 0, total_len = 0;

	hdr_len = (ETH_HDR_LEN + L2_HDR_LEN);
	payloadLen = (sizeof(struct tlv) + strlen(buff));
	total_len = (hdr_len + payloadLen);

	pkt = (char *)calloc(total_len, sizeof(char));
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
	if(strcmp((char *)destMac, (char *)nillMac) == 0)
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

	memset(&tlv_buff, '\0', sizeof(struct tlv));
	tlv_buff.tlv_type = (unsigned char) HELLO_INFO;
	tlv_buff.len = htonl(strlen(buff));
	memcpy(payload, &tlv_buff, sizeof(struct tlv));
	payload += sizeof(struct tlv);

	memcpy(payload, buff, payloadLen);
	payload += payloadLen;

	saddr_ll.sll_ifindex = if_nametoindex(intfName);
	saddr_ll.sll_halen = ETH_ALEN;
	saddr_ll.sll_addr[6] = 0x00;
	saddr_ll.sll_addr[7] = 0x00;

	send_len = sendto(sockId, pkt, total_len, 0, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll));
	if(send_len < 0)
	{
		printf("Failed to send the '%s' to l2_client\n", buff);
		free(pkt);
		return -1;
	}

	free(pkt);
	return 0;
}

int get_ifMacAddr(int sockId, const char *intfName, unsigned char *mac)
{
	struct ifreq ifr;

	memset(&ifr, '\0', sizeof(ifr));
	strncpy(ifr.ifr_name, intfName, strlen(intfName));
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
		printf("Usage: %s <interface name> [destnation mac if known]\n", argv[0]);
		return -1;
	}

	int sock_Id = 0;
	struct sockaddr_ll sock_addr;
	struct sock_fprog bpf;
	char msgBuff[MAX_BUFF_LEN] = {'\0'};
	unsigned char dstMac[ETH_ALEN] = {'\0'};

	strcpy(intfName, argv[1]);
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
	sock_addr.sll_ifindex = if_nametoindex(intfName);
	if(bind(sock_Id, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
	{
		printf("Unable to bind the raw socket to interface: %s\n", intfName);
		close(sock_Id);
		return -1;
	}

	//Setting socket option to filter only My own L2 protocol Msgs
	bpf.len = (sizeof(my_l2Msg_filter)/sizeof(my_l2Msg_filter[0]));
	bpf.filter = my_l2Msg_filter;
	if(setsockopt(sock_Id, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
	{
		printf("Unable to set the socket option to filter own L2 msgs\n");
		close(sock_Id);
		return -1;
	}

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

	close(sock_Id);
	return 0;
}
