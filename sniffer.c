/*
Author: Joel Schofield <joel.n.schofield@gmail.com>
Note: 	PROGRAM MUST BE RUN AS SUDO. The program uses bash commands which need
		root permissions to work.
*/
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h> 
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include "Radiotap.h"
#include "MQTTClient.h"
#include "radiotap_iter.h"

#define PROMISCUOUS_MODE_ON 		1
#define PROMISCUOUS_MODE_OFF 		0
#define MAC_FILTER_STRING_OFFSET 	15
#define MAC_STRING_LENGTH 			17
#define NODE_ID_LEN 				200
#define DEVICE_LEN 					200
#define FILTER_LEN 					256
#define HOSTNAME_LEN 				200
#define TOPIC_LEN	 				200
#define MESSAGE_BUFF_LEN 			200
#define CMD_BUFF_LEN	 			200
#define PORT_LEN 					200
#define CONF_KEY_OFFSET 			5

#define QOS         1
#define TIMEOUT     10000L


//radiotap required structures.
static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};


//radiotap header, with fields configured for black pi wifi.
typedef struct {
		//header
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */

        //data
        //u_int64_t 		tsft;
        u_int32_t 		pad;
        u_int8_t		flags;
        u_int8_t		rate;
        //u_int16_t		ch_freq;
        //u_int16_t		ch_type;
        int8_t			ant_sig;
        int8_t			ant_noise;
        int8_t			lock_quality;
        u_int8_t		ant;
        
} __attribute__((__packed__)) ieee80211_radiotap;

//ethernet packet header.
typedef struct {
	unsigned short			fc;		/* frame control */
	unsigned short			durid;		/* duration/ID */
	u_char	a1[6];		/* address 1 */
	u_char	a2[6];		/* address 2 */
	u_char	a3[6];		/* address 3 */
	unsigned short			seq;		/* sequence control */
	u_char	a4[6];		/* address 4 */
} __attribute__((__packed__)) dot11_header;


//my mac 		28:37:37:18:fd:c6
//my iphone		44:4c:0c:c2:ad:28
//eduroam 		64:d9:89:43:7f:5e

//function prototypes:
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
struct in_addr* name_to_IP_addr(char* hostname);
int connect_to(struct in_addr* ipAddress, int port);
void print_mac(FILE * stream,u_char * mac);
void delivered(void *context, MQTTClient_deliveryToken dt);
int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message);
void connlost(void *context, char *cause);
void *channel_hopping_thread (void *arg);

//global variables.

//radiotap globals.
static int fcshdr = 0;

//MQTT globals.
MQTTClient client;
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
MQTTClient_message pubmsg = MQTTClient_message_initializer;
MQTTClient_deliveryToken token;
volatile MQTTClient_deliveryToken deliveredtoken;
int rc;

//thread globals
volatile u_int8_t wifi_channel;

//config data.
char topic[TOPIC_LEN];
char node_id[NODE_ID_LEN];
char dev[DEVICE_LEN]; // string for holding target network device to listen on.
char filter_exp[FILTER_LEN]; //  = "ether dst host 64:d9:89:43:7f:5e";		//string for filter expression.
char hostname[HOSTNAME_LEN];


int main(int argc, char *argv[])
{	
	
	char errbuf[PCAP_ERRBUF_SIZE]; 	// buffer to hold error messages.
	pcap_t *handle; 				// session handle.
	struct bpf_program fp;		/* The compiled filter */
	struct pcap_pkthdr pack_header;		// the header that pcap gives us
	const u_char *packet;		/* The actual packet */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	int i;
	char readBuff[1024];
	char *tgtPtr;
	int status;
	pthread_t tid;

	FILE * confStream;

	//read in the configuration file to load settings for sniffing.
	confStream = fopen("/home/pi/Sniffer/MQTTVersion/sniffer_config", "r");
	if (confStream == NULL) {
		fprintf(stderr, "No sniffer_config file found.");
		return (2);
	}

	fprintf(stdout, "Loading config...\n");
	fflush(stdout);

	while ( fgets (readBuff, 1024, confStream) != NULL) {

		if ( strncmp("nid: ", readBuff, CONF_KEY_OFFSET) == 0 )
			tgtPtr = node_id;
		else if ( strncmp("dev: ", readBuff, CONF_KEY_OFFSET) == 0 )
			tgtPtr = dev;
		else if ( strncmp("flt: ", readBuff, CONF_KEY_OFFSET) == 0 )
			tgtPtr = filter_exp;
		else if ( strncmp("adr: ", readBuff, CONF_KEY_OFFSET) == 0 )
			tgtPtr = hostname;
		else if ( strncmp("top: ", readBuff, CONF_KEY_OFFSET) == 0 )
			tgtPtr = topic;
		else
			continue;

		for (i = CONF_KEY_OFFSET; readBuff[i] != '\0' && readBuff[i] != '\n' && readBuff[i] != '\r'; i++) {

			tgtPtr[i - CONF_KEY_OFFSET] = readBuff[i];
		}

		tgtPtr[i - CONF_KEY_OFFSET] = '\0';
	}

	fprintf(stdout, "Load done.\n");
	fprintf(stdout, "nid: %s\n", node_id);
	fprintf(stdout, "dev: %s\n", dev);
	fprintf(stdout, "flt: %s\n", filter_exp);
	fprintf(stdout, "adr: %s\n", hostname);
	fflush(stdout);


	//lookup netmask information.
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	//loop forever until a session is successfully started.
	while (1) {

		//create a listening session.
		handle = pcap_create(dev, errbuf);
		if(handle == NULL) {
		    printf("pcap_create failed: %s\n", errbuf);
		    printf("retrying shortly..\n");
		    sleep(3);
		    continue;
		}
	    break;
	}
	


	//setup session.
	pcap_set_snaplen(handle, BUFSIZ);  // Set the snapshot length to BUFSIZ
	pcap_set_promisc(handle, PROMISCUOUS_MODE_ON); // Turn promiscuous mode on
	pcap_set_timeout(handle, 1000); // Set the timeout to 512 milliseconds

	fprintf(stderr, "pcap_can_set_rfmon: %d\n", pcap_can_set_rfmon(handle) );

	//set monitor mode on, enabling sniffing of packets that are not directed at running machine.
	if(pcap_set_rfmon(handle, 1) != 0)
	    printf("monitor mode not available\n");

	//start listening.
	while ((status = pcap_activate(handle) ) != 0) {
		printf("activation failed: %d\n", status);
	    printf("retrying shortly..");
	    sleep(3);
	}
	
	
	//Compile and apply the filter.
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		//return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		//return(2);
	}
	
	//determine the link type of the connection.
	printf("link-type: %s\n", pcap_datalink_val_to_name(pcap_datalink(handle)));

	printf("hostname is: %s\n node_id is: %s\n", hostname, node_id);

	//create new MQTT session.
	MQTTClient_create(&client, hostname, node_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    //callbacks allow for multiple threads; prevents program from hanging while waiting for
    //QoS
    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);

    //connect to MQTT server.
    while ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("MQTT Failed to connect, return code %d\n", rc);
        printf("retrying shortly...\n");
        sleep(3);
        //exit(-1);       
    }

    fprintf(stdout, "Connected to MQTT server at %s\n", hostname);

    //create the channel hopping thread to flick through the channels.
    pthread_create (&tid, NULL, channel_hopping_thread, 0);

	//loop forever processing packets.
	pcap_loop(handle, -1, got_packet, 0);

	//should not get here unless an error occurs from grabbing packets.
	fprintf(stderr, "error: left pcap_loop.\n");

	//close the listening session.
	pcap_close(handle);

	return(0);
}






void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	//quickly grab the wifi channel incase it changes while processing the packet.
	u_int8_t packet_channel = wifi_channel;

	char messageBuff[MESSAGE_BUFF_LEN]; //buffer for storing a message to be sent.

	int err;
	int radiotap_header_len;
	int8_t rssi;
	struct ieee80211_radiotap_iterator iter;

	err = ieee80211_radiotap_iterator_init(&iter, (void*)packet, 25, &vns);
	if (err == 0) 
		fprintf(stdout, "all good!\n");
	else 
		fprintf(stdout, "all bad! %d\n", err);

	//extract the length of the header.
	radiotap_header_len = iter._max_length; 

	//sanity printf of header length.
	printf("header length: %d\n", radiotap_header_len);

	//loop through the packet, looking for the desired data (rssi)
	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {

		if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
			rssi = (int8_t)iter.this_arg[0];
			printf("antsignal is: %d\n", rssi);
		}
	}

	//cast received packet into ethernet packet header. the size of the radiotap header can change, hence cannot
	//be cast statically. 
	dot11_header * dot_head = (dot11_header*) (packet + radiotap_header_len * sizeof(char) );
	printf("dest: "); print_mac(stdout, dot_head->a1); printf("\n");
	printf("src:"); print_mac(stdout, dot_head->a2); printf("\n");

	/*
	for (int i=0; i < 64; i++) {
		if (i%4 == 0 && i != 0)
			fprintf(stdout, "\n");
		fprintf(stdout, "%0.2x", packet[i]);
	}
	fprintf(stdout, "\n");
	*/


	sprintf(messageBuff, "{\"node_id\":\"%s\",\"channel\":%d,\"rssi\":%d,\"macSrc\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}", 
		node_id,
		packet_channel,
		rssi, 
		dot_head->a2[0],
		dot_head->a2[1],
		dot_head->a2[2],
		dot_head->a2[3],
		dot_head->a2[4],
		dot_head->a2[5]
		);

	
	pubmsg.payload = messageBuff;
    pubmsg.payloadlen = strlen(messageBuff);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    deliveredtoken = 0;
    MQTTClient_publishMessage(client, topic, &pubmsg, &token);

    //remove acknowledgements.
    
    printf("Waiting for publication of %s\n"
            "on topic %s for client with ClientID: %s\n",
            messageBuff, topic, client);
    while(deliveredtoken != token);
    

    //MQTTClient_disconnect(client, 10000);
    //MQTTClient_destroy(&client);


}




void *channel_hopping_thread (void *arg) {

	char cmdBuff[CMD_BUFF_LEN];

	wifi_channel = 1;
	
	while (1) {

		//can use fact that, in US and Australia, channels 1 6 and 11 are used for wifi.
		//This is due to the 25MHz spectrum of each channel, which would overlap if, for example,
		//channels 1 and 2 were used simultaneously.
		switch ( wifi_channel ) {
			case 1:
				wifi_channel = 6;
				break; 
			case 6:
				wifi_channel = 11;
			 	break; 
			case 11:
				wifi_channel = 1;
			 	break; 
		}

		sprintf(cmdBuff, "iwconfig wlan0 channel %d", wifi_channel);
		
		system(cmdBuff);

		fprintf(stdout, "new channel: %d\n", wifi_channel);

		usleep(10000);
	}
	
}




void print_mac(FILE * stream,u_char * mac) {
	for (int i=0; i < 6; i++) {
		fprintf(stream, "%.2x", mac[i]);
	}
}






void delivered(void *context, MQTTClient_deliveryToken dt)
{
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    int i;
    char* payloadptr;

    printf("Message arrived\n");
    printf("     topic: %s\n", topicName);
    printf("   message: ");

    payloadptr = message->payload;
    for(i=0; i<message->payloadlen; i++)
    {
        putchar(*payloadptr++);
    }
    putchar('\n');
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}





void connlost(void *context, char *cause)
{
    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);
}
