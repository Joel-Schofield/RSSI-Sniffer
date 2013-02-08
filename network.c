#include "network.h"


struct in_addr* name_to_IP_addr(char* hostname)
{
    int error;
    struct addrinfo* addressInfo;

    /* Converting hostname into address information (IP address) */
    error = getaddrinfo(hostname, NULL, NULL, &addressInfo);
    if(error) {
	return NULL;
    }
    /* Extract IP address and return */
    return &(((struct sockaddr_in*)(addressInfo->ai_addr))->sin_addr);
}

/* Port number will be host order */
int connect_to(struct in_addr* ipAddress, int port)
{
    struct sockaddr_in socketAddr;
    int fd;
    
    /* Create TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
	perror("Error creating socket");
	exit(1);
    }

    /* Set up an address structure that contains the address
     * (IP address and port number) that we're trying to connect to.
     */
    socketAddr.sin_family = AF_INET;	/* IP v4 */
    socketAddr.sin_port = htons(port);	/* port number in network byte order */
    socketAddr.sin_addr.s_addr = ipAddress->s_addr;	/* IP address */

    /* Attempt to connect to remote address */
    if(connect(fd, (struct sockaddr*)&socketAddr, sizeof(socketAddr)) < 0) {
	perror("Error connecting");
	exit(1);
    }

    return fd;
}