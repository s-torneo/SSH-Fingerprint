  #include <stdio.h>
  #include <string.h>
  #include <pcap.h>
  #include <stdlib.h>
  #include <netinet/in.h>
  #include <netinet/if_ether.h>

  #include <openssl/md5.h>


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

  char *ssh_protocol;

  /* calcola la fingerprint */
  void md5(char *algorithms, char *fingerprint){
    unsigned char result [MD5_DIGEST_LENGTH];
    MD5((unsigned char*)algorithms, strlen(algorithms), result);
    for(int i = 0; i < 16; i++)
      sprintf(&fingerprint[i*2], "%02x", (unsigned int)result[i]);
  }

  /* prende gli algoritmi di hash dal payload separandoli con ';' */
  void Split(char *str, int *sum){
    const u_char *temp_pointer = (payload + 26); /* 26 byte = 4 byte packet length + 1 byte padding length 
    + 1 byte msg code + 16 byte ssh cookie + 4 kex_algorithms_length */
    for (int i = 0, counter = 0; i < payload_length; i++, counter++) {
      if ((temp_pointer[i] >= 32 && temp_pointer[i] <= 126) || temp_pointer[i] == 10 || temp_pointer[i] == 11 || temp_pointer[i] == 13)
        str[i]=temp_pointer[i];
      else {
        str[i]=';';
        *(sum) += counter;
        counter = -1;
      }
    }
  }
  
  /* concatena gli algoritmi di hash interessati */
  void Concat_Algorithms(char *algorithms, char *str, int split_counter){
    int i = 0, flag = 0, counter_alg = 0;
    while(i < split_counter){
      while(str[i] == ';')
        i++;
      if(str[i-1] == ';'){
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

  /*void PrintInfo(const struct pcap_pkthdr *header){
    printf("\nTotal packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);
    printf("IP header length in bytes: %d\n", ip_header_length);
    printf("Total size of headers: %d bytes\n", total_headers_size);
    printf("Payload len: %d bytes\n", payload_length);
  }*/

  void GetSSHProtocol(char *ssh_protocol){
    const u_char *temp_pointer = payload;
    int i = 0;
    while(i < payload_length){
      ssh_protocol[i] = temp_pointer[i];
      i++;
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

    /* uint32_t len = (uint32_t)*(payload + 4);
    long len1 = ntohl(len); 
    printf("\n\n len: %d",len); */

    if (payload_length > 7 && payload_length < 100 && memcmp(payload,"SSH-",4) == 0) {
      //PrintInfo(header);
      ssh_protocol = calloc(payload_length,sizeof(char));
      GetSSHProtocol(ssh_protocol);
    }
    else if(payload_length > 1000 && payload_length < 1500){
      //PrintInfo(header);
      char *split = calloc(payload_length,sizeof(char));
      int split_counter = 0;
      Split(split, &split_counter);
      char *algorithms = calloc(split_counter,sizeof(char));
      Concat_Algorithms(algorithms, split, split_counter);
      free(split);
      printf("%s\n\n",algorithms);
      char *fingerprint = calloc(33,sizeof(char));
      md5(algorithms, fingerprint);
      printf("%s - %s\n",fingerprint, ssh_protocol);
      free(fingerprint);
      free(ssh_protocol);
      free(algorithms);
    }
    return;
  }

  static void help() {
    printf("filter <device or pcap>\n");
    printf("Example: ./filter sample_ssh.pcap\n");
    exit(0);
  }

  int main(int argc, char **argv) {
    const char *dev = "lo";
    pcap_t *handle = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "dst port 22 or dst port 2222";
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

    pcap_loop(handle,-1, my_packet_handler,NULL);
    pcap_close(handle);

    return 0;
  }
