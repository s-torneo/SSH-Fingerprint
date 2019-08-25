  #include <stdio.h>
  #include <string.h>
  #include <pcap.h>
  #include <stdlib.h>
  #include <netinet/in.h>
  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  
  #include "md5_nDPI.h"
  #include "hash.c"


  /* Pointers to headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  /* Header lengths in bytes */
  int ethernet_header_length = 14;
  int ip_header_length;
  int tcp_header_length;
  int payload_length;
  int total_headers_size;

  /* struct header */
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;

  /* prende gli algoritmi d i hash dal payload separandoli con ';' */
  void Split(char *str, int *sum){
    const u_char *temp_pointer = (payload + 26); /* 26 byte = 4 byte packet length + 1 byte padding length 
    + 1 byte msg code + 16 byte ssh cookie + 4 kex_algorithms_length */
    for (int i = 0; i < payload_length; i++) {
      if ((temp_pointer[i] >= 32 && temp_pointer[i] <= 126) || temp_pointer[i] == 10 || temp_pointer[i] == 11 || temp_pointer[i] == 13){
        str[*sum]=temp_pointer[i];
        *(sum)+=1;
      }
      else {
        str[*sum]=';';
        *(sum)+=1;
        i+=3; // numero dei byte per andare all'algoritmo di hash successivo
      }
    }
  }
  
  /* concatena gli algoritmi di hash interessati */
  void Concat_Algorithms(char *algorithms, char *str, int split_counter){
    int i = 0, flag = 0, counter_alg = 0;
    while(i < split_counter){
      int tmp = i;
      while(str[i] == ';')
        i++;
      if(abs(i-tmp)>1)
        i = split_counter;
      else if(str[i-1] == ';'){
        flag++;
        if(i < split_counter-1 && !(flag%2)){
          algorithms[counter_alg++] = str[i-1];
        }
      }
      if(!(flag % 2)){
        algorithms[counter_alg++] = str[i];
      }
      i++;
    }
  }

  void GetSSHProtocol(char *ssh_protocol){
    const u_char *temp_pointer = payload;
    int i = 0;
    while(i < payload_length){
      ssh_protocol[i] = temp_pointer[i];
      i++;
    }
  } 

  void IP_TCP_info(char *sourceIP, char *destIP, int *sourcePort, int *destPort){
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    *(sourcePort) = ntohs(tcpHeader->source);
    *(destPort) = ntohs(tcpHeader->dest); 
  }

  void PrintInfo(){
    for(int i=0;i<HASHTOT;i++){
        SSH *ptr=ssh[i]; 

      if(ssh[i]!=NULL && ssh[i]->completed>1 ){
        printf("[-] Client SSH_MSG_KEXINT detected ");
        printf("[%s:%d -> %s:%d]\n",ptr->ip_source_client,ptr->port_source_client,ptr->ip_dest_client,ptr->port_dest_client);
        printf("[-] SSH Protocol: %s",ptr->ssh_protocol_client);
        printf("[-] hassh: ");
        for(int j=0; j<16; j++)
          printf("%02x", ptr->fingerprint_client[j]);
        printf("\n[-] hassh Algorithms: %s\n",ptr->algorithms_client);
        printf("\n[-] Server SSH_MSG_KEXINT detected ");
        printf("[%s:%d -> %s:%d]\n",ptr->ip_source_server,ptr->port_source_server,ptr->ip_dest_server,ptr->port_dest_server);
        printf("[-] SSH Protocol: %s",ptr->ssh_protocol_server);
        printf("[-] hassh:  ");
        for(int j=0; j<16; j++)
          printf("%02x", ptr->fingerprint_server[j]);
        printf("\n[-] hassh Algorithms: %s\n\n",ptr->algorithms_server);
        for(int i=0;i<80;i++)
          printf("-");
        printf("\n\n");
      }
    }
  }

  
  void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
      printf("Not an IP packet. Skipping...\n\n");
      return;
    }

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
      printf("Not a TCP packet\n\n");
      return;
    }

    /* pointer to struct heade r */
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    /* Add the ethernet and ip header length to the start of the packet
      to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    /* Add up all the header sizes to find the payload offset */
    total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;

    payload_length = header->caplen -(ethernet_header_length + ip_header_length + tcp_header_length);

    if(payload_length == 0) return;

    payload = packet + total_headers_size;

    char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    int sourcePort, destPort;
    IP_TCP_info(sourceIP, destIP, &sourcePort, &destPort);
    
    if (payload_length > 7 && payload_length < 100 && memcmp(payload,"SSH-",4) == 0) {
      if(destPort == 22 || destPort == 2222){
        SSH* ptr = FindPositionHash(sourceIP, destIP,sourcePort, destPort);
        GetSSHProtocol(ptr->ssh_protocol_client);
        strcpy(ptr->ip_source_client,sourceIP);
        ptr->port_source_client = sourcePort; 
        strcpy(ptr->ip_dest_client,destIP);
        ptr->port_dest_client = destPort;
      }
      else {
        SSH* ptr = FindPositionHash(sourceIP, destIP,sourcePort, destPort);
        GetSSHProtocol(ptr->ssh_protocol_server);
        strcpy(ptr->ip_source_server,sourceIP);
        ptr->port_source_server = sourcePort;
        strcpy(ptr->ip_dest_server,destIP); 
        ptr->port_dest_server = destPort;
      }
    }
    else if(payload_length > 300 && payload_length < 2000){
      u_int8_t msgcode = *(payload + 5);
      //printf("\nmsg: %u\n",msgcode);
      /*u_int8_t padding = *(payload + 4); */
      if(msgcode == 20){
        char *split = calloc(payload_length,sizeof(char));
        int split_counter = 0;
        Split(split, &split_counter);
        if(destPort == 22 || destPort == 2222){
          SSH* ptr =  FindPositionHash(sourceIP, destIP,sourcePort, destPort);
          Concat_Algorithms(ptr->algorithms_client, split, split_counter);
          free(split);
          MD5_CTX ctx;
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ptr->algorithms_client, strlen(ptr->algorithms_client));
          MD5Final(ptr->fingerprint_client, &ctx);
          ptr->completed++;
        }
        else {
          SSH* ptr =  FindPositionHash(sourceIP, destIP,sourcePort, destPort);
          Concat_Algorithms(ptr->algorithms_server, split, split_counter);
          free(split);
          MD5_CTX ctx;
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ptr->algorithms_server, strlen(ptr->algorithms_server));
          MD5Final(ptr->fingerprint_server, &ctx);
          ptr->completed++;
        }
      }
    }
    return;
  }

  static void help() {
    printf("filter <device or pcap>\n");
    printf("Example: ./filter sample_ssh.pcap\n");
    exit(0);
  }

  int main(int argc, char **argv) {
    InitHash();
    const char *dev = "lo";
    pcap_t *handle = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "port 22 or port 2222";
    bpf_u_int32 subnet_mask, ip;

    if(argc == 1)
      help();

    dev = argv[1];

    if(strstr(dev, ".pcap")) {
      handle = pcap_open_offline(dev, error_buffer);
      if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
      }
    } else {
      if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
      }

      handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
      if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
      }
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
      printf("Bad filter - %s\n", pcap_geterr(handle));
      return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
      printf("Error setting filter - %s\n", pcap_geterr(handle));
      return 2;
    }

    //ssh = calloc(1,sizeof(SSH));

    pcap_loop(handle,-1, my_packet_handler,NULL);
    pcap_close(handle);
    PrintInfo();
    DestroyHash();
    return 0;
  }
