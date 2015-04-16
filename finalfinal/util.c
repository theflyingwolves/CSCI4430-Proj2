#include "util.h"

uint32_t publicIP=0;
uint32_t internalIP=0;
uint32_t subnetIP=0;
unsigned int mask=0xFFFFFFFF;

tcpEntry tcpHead;
udpEntry udpHead;


int processUdp(udpEntry *table, struct ip* packet, double currentTime){
    
    int direction = getDirection(packet,publicIP);

    if (direction == 0) {
        // It is an outgoing package
        fprintf(stdout,"Outgoing! \n");        
        struct udphdr* udp_hdr = (struct udphdr*) ( (unsigned char*)packet + (packet->ip_hl << 2) );
        
        // Search for UDP entry
        uint32_t ip_src = ntohl(packet->ip_src.s_addr);
        uint16_t sport = ntohs(udp_hdr->source);
        udpEntry * entry = findOutUdp(table,ip_src,sport);
        
        int transPort;
        if ( entry == NULL  ) {
            /* No record yet. Insert Entry */
            
            transPort = insertEntry(table,packet,currentTime);

            if (transPort==-1) {
               // Return 0 to indicate drop package
                return 0;
            }
        }else if(currentTime - entry->createTime > 30){
            /* Record found, but has expired. */
            
            // Remove UDP entry
            removeUdp(entry);
            
            // Insert new UDP entry
            transPort = insertEntry(table,packet,currentTime);
            
            if (transPort==-1) {
                // Port exhausted. Return 0 to indicate Package Drop
                return 0;
            }
            
        }else{
            /* Record found and valid. Reset the clock! */
            entry->createTime = currentTime;
            
            transPort = entry->transPort;
        }
        

        /*
         Change the source IP address to that of VM A and the source port number to transPort
         */
        packet->ip_src.s_addr = htonl(publicIP);
        udp_hdr->source = htons(transPort);
        
        // Update checksum
        packet->ip_sum = ip_checksum((unsigned char *)packet);
        udp_hdr->check= udp_checksum((unsigned char *)packet);
        
        // return 1 to let Callback function know we need to accept the packet.
        return 1;
        
    }else{
        // It is an incoming package
	      fprintf(stdout,"Incoming!\n");
        struct udphdr* udp_hdr = (struct udphdr*) ( (unsigned char*)packet + (packet->ip_hl << 2) );
        
        // Search for udp entry
        uint16_t dport = ntohs(udp_hdr->dest);
        udpEntry *entry = findInUdp(table,dport);

        if (entry == NULL || currentTime - entry->createTime > 30) {
            // Either entry not found or entry has expired
            // return 0 to let Callback function know we need to drop the packet.
            return 0;
        }else{
            // Record found, and valid, reset the clock
            entry -> createTime = currentTime;
            
            // Modify packet
            packet->ip_dst.s_addr = htonl(entry->ip);
            udp_hdr->dest = htons(entry->port);
            
            // Update checksum
            udp_hdr->check = udp_checksum((unsigned char *)packet);
            packet->ip_sum = ip_checksum((unsigned char *)packet);
        }
        
        return 1;
    }
}

int processTcp(tcpEntry *table, struct ip* packet) {
	int direction = getDirection(packet, publicIP);
	
	
        struct tcphdr* tcp_hdr = (struct tcphdr*) ( (unsigned char*) packet + (packet->ip_hl << 2) );
	

	if (direction == 0) {
    fprintf(stdout,"Outgoing!\n");
		// It is an outgoing packet

        // Search for matching entry
        uint32_t ip_src = ntohl(packet->ip_src.s_addr);
        uint16_t sport = ntohs(tcp_hdr->source);
        tcpEntry * entry = findOutTcp(table, ip_src, sport);

        uint16_t transPort;
        if ( entry == NULL ) {
            // No record yet.
            
            if (tcp_hdr->syn == 1) {
                // SYN packet & Entry NULL
                // create a new entry in the translation table
                transPort = insertTcpEntry(table, packet);
            } else {
                // Non-SYN packet & Entry NULL
                // Drop the packet
                return 0;
            }
        } else {
            // Record found.
            transPort = entry->transPort;
        }
        
        // Modify packet
        packet->ip_src.s_addr = htonl(publicIP);
        tcp_hdr->source = htons(transPort);
        
        // Update checksum
        packet->ip_sum = ip_checksum((unsigned char *)packet);
        tcp_hdr->check = tcp_checksum((unsigned char *)packet);

        return 1;
  }else if (direction == 1) {
    // Incoming packet
      fprintf(stdout,"Incoming!\n");
      
      // Search Entry
    uint16_t dport = ntohs(tcp_hdr->dest);
    tcpEntry *entry = findInTcp(table, dport);

    if (entry == NULL) {
        // Record not found
      return 0;
    } else {
        // Record found.
	 int isRST = 0;
	 if (tcp_hdr->rst==1) {
		// Handling RST
		fprintf(stdout,"RST!!\n");
		isRST  = 1;
         }

          packet->ip_dst.s_addr = htonl(entry->ip);
          tcp_hdr->dest = htons(entry->port);
          tcp_hdr->check = tcp_checksum((unsigned char*)packet);
          packet->ip_sum = ip_checksum((unsigned char*)packet);

	  if (isRST == 1){
	  	removeTcp(entry);
	  }
          return 1;
    }
  }else{
      return 0;
  }
}

int getDirection(struct ip* packet, uint32_t Aip){
    uint32_t desip = ntohl(packet->ip_dst.s_addr); 
    
    if ( desip  == Aip) {
        // If the destination ip is the same as the ip of VM A, then it is an incoming package.
        return 1;
    }
    else{
        // Otherwise, it is an outgoing package.
        return 0;
    }
}

int insertEntry(udpEntry *table,struct ip* packet,double currentTime){
    int transPort = getAvailableTransport(currentTime);
    struct udphdr* udp_hdr = (struct udphdr*) ( (unsigned char*)packet + (packet->ip_hl << 2) );
    if (transPort > 0) {
        uint32_t srcip = ntohl(packet->ip_src.s_addr);
        // port?
        uint16_t port = ntohs(udp_hdr->source);
        addUdp(table,srcip,port,transPort,currentTime);
        return transPort;
    }else{
        // return -1, we will drop this packet cause the port number is full.
        return transPort;
    }
}


int getAvailableTransport(double currentTime){
    uint16_t port = 10000;
    int i;
    for (i=0; i<=2000; i++) {
        port = 10000 + i;
        udpEntry * res = findInUdp(&udpHead,port);
        tcpEntry * res2= findInTcp(&tcpHead,port);
	if (res && (currentTime - res->createTime > 30)){
		removeUdp(res);
		res = NULL;
	}

        if (!res && !res2) {
            return port;
        }
    }
    return -1;
}

int insertTcpEntry(tcpEntry *table, struct ip* packet) {
  double currentTime = (double) time(0);
  int transPort = getAvailableTransport(currentTime);
  struct tcphdr* tcp_hdr = (struct tcphdr*) ( (unsigned char*)packet + (packet->ip_hl << 2));
  if (transPort > 0) {
    uint32_t srcip = ntohl(packet->ip_src.s_addr);
    uint16_t port = ntohs(tcp_hdr->source);
    addTcp(table,srcip,port,transPort);
    return transPort;
  } else {
    return transPort;
  }
}
