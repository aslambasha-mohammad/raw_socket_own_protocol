#include "l2_header.h"

char intfName[32] = {'\0'};
unsigned char intfMac[ETH_ALEN] = {'\0'};
unsigned char destMac[ETH_ALEN] = {'\0'};

int recv_l2Msg(int sockId, char *buff, enum my_msgType type)
{
	char *pkt = NULL;
	struct tlv 	*tlv_buff = NULL;
	struct my_l2_hdr *msgHdr = NULL;
	struct ethhdr	*ethHdr = NULL;
	char *payload = NULL;
	unsigned int hdr_len = 0, total_len = 0, payloadLen = 0;
	unsigned int recv_len = 0;

	hdr_len = (ETH_HDR_LEN + L2_HDR_LEN);
	total_len = hdr_len + MAX_MSG_SIZE;

	pkt = (char *)calloc(total_len, sizeof(char));
	if(pkt == NULL)
	{
		printf("Unable to allocate memory to receive packet\n");
		return -1;
	}

	recv_len = recv(sockId, pkt, total_len, 0);
	if(recv_len > 0)
	{
		ethHdr = (struct ethhdr *)pkt;
		msgHdr = (struct my_l2_hdr *)(pkt + ETH_HDR_LEN);
		payload = (pkt + hdr_len);

		if(ntohs(ethHdr->h_proto) != ETH_MY_PROTO)
		{
			printf("Received packet is not my own L2 protocol\n");
			goto failure;
		}

		if((msgHdr->msgType != HELLO_MSG) && (msgHdr->msgType != BYE_MSG))
		{
			printf("Received msgType is neither HELLO nor BYE\n");
			goto failure;
		}

		if(ntohs(msgHdr->hdrLen) != L2_HDR_LEN)
		{
			printf("Received packet's L2 header len doesn't match. Rejecting it\n");
			goto failure;
		}

		payloadLen = ntohl(msgHdr->payloadLen);
		if(payloadLen > MAX_MSG_SIZE)
		{
			printf("Received packet payload doesn't match. Rejecting it\n");
			goto failure;
		}

		if(recv_len < (ETH_HDR_LEN + L2_HDR_LEN + payloadLen))
		{
			printf("Received packet length is less than the expected length\n");
			goto failure;
		}

		while(payloadLen)
		{
			tlv_buff = (struct tlv *)payload;
			payload += sizeof(struct tlv);
			payloadLen -= sizeof(struct tlv);
			switch(tlv_buff->tlv_type)
			{
				case HELLO_INFO:
				{
					memcpy(buff, payload, tlv_buff->len);
					payload += tlv_buff->len;
					payloadLen -= tlv_buff->len;
				}
				break;
				case BYE_INFO:
				{
					memcpy(buff, payload, tlv_buff->len);
					payload += tlv_buff->len;
					payloadLen -= tlv_buff->len;
				}
				break;
				default:
					printf("Undefined TLV Type received\n");
			}
		}
	}
	free(pkt);
	return 0;

failure:
	free(pkt);
	return -1;
}

int get_ifMacAddr(int sockId, const char *intfName, unsigned char *mac)
{
	struct ifreq ifr;

	memset(&ifr, '\0', sizeof(ifr));
	strncpy(ifr.ifr_name, intfName, strlen(intfName));
	ifr.ifr_ifindex = if_nametoindex(intfName);
	if(ioctl(sockId, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Unable to fetch the Mac of '%s' interface\n", intfName);
		return -1;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf("Usage: %s <interface name>\n", argv[0]);
		return -1;
	}
	strcpy(intfName, argv[1]);

	int sock_Id = 0;
	struct sockaddr_ll sock_addr;
	struct sock_fprog bpf;
	char msgBuff[MAX_BUFF_LEN] = {'\0'};

	sock_Id = socket(PF_PACKET, SOCK_RAW, htons(ETH_MY_PROTO));
	if(sock_Id < 0)
	{
		printf("Failed to create the Raw socket for '%s' interface\n", intfName);
		return -1;
	}

	memset(&sock_addr, '\0', sizeof(sock_addr));
	sock_addr.sll_family = AF_PACKET;
	sock_addr.sll_ifindex = if_nametoindex(intfName);

	if(bind(sock_Id, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
	{
		printf("Unable to bind the raw socket to '%s' interface\n", intfName);
		close(sock_Id);
		return -1;
	}

	memset(&bpf, '\0', sizeof(bpf));
	bpf.len = (sizeof(my_l2Msg_filter)/sizeof(my_l2Msg_filter[0]));
	bpf.filter = my_l2Msg_filter;

	if(setsockopt(sock_Id, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
	{
		printf("Unable to set the socket option to filter own L2 msg\n");
		close(sock_Id);
		return -1;
	}

	if(get_ifMacAddr(sock_Id, intfName, intfMac) != 0)
	{
		printf("Failed to extract the interface MAC or Invalid interface provided\n");
		close(sock_Id);
		return -1;
	}

	printf("Waiting for the L2 Msg from l2_server\n");
	if(recv_l2Msg(sock_Id, msgBuff, HELLO_MSG) != 0)
	{
		printf("Failed to receive the L2 msg from l2_server\n");
	}
	printf("***** Received '%s' from l2_server *****\n", msgBuff);

	close(sock_Id);
	return 0;
}
