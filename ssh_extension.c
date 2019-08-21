/*
 * ssh.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-18 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SSH

#include "ndpi_api.h"
#include "md5_nDPI.h"


  typedef struct _SSH{
    char ssh_protocol_client[100];
    char algorithms_client[2000];
    u_char fingerprint_client[16];
    u_int32_t ip_source_client;
    u_int32_t ip_dest_client;
    u_int32_t port_source_client;
    u_int32_t port_dest_client;
    char ssh_protocol_server[100];
    char algorithms_server[2000];
    u_char fingerprint_server[16];
    u_int32_t ip_source_server;
    u_int32_t ip_dest_server;
    u_int32_t port_source_server;
    u_int32_t port_dest_server;
    int completed;
  }SSH;

  // array di struttura SSH
  SSH ssh[255];

  // contatore per l'array SSH
  int ncount = 0;


static void ndpi_int_ssh_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow){
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSH, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_ssh_zap_cr(char *str, int len) {
  len--;

  while(len > 0) {
    if((str[len] == '\n') || (str[len] == '\r')) {
      str[len] = '\0';
      len--;
    } else
      break;
  }
}


int GetPos(u_int32_t sourceIP, u_int32_t destIP,u_int32_t sourcePort, u_int32_t destPort){
  for(int i = 0; i < ncount; i++) {
    /*if(!strcmp(sourceIP,ssh[i].ip_source_client) && !strcmp(destIP,ssh[i].ip_dest_client) && sourcePort==ssh[i].port_source_client && destPort==ssh[i].port_dest_client)
      return i;
    else if(!strcmp(sourceIP,ssh[i].ip_source_server) && !strcmp(destIP,ssh[i].ip_dest_server) && sourcePort==ssh[i].port_source_server && destPort==ssh[i].port_dest_server)
      return i;*/
    if((destIP == ssh[i].ip_source_client) && (sourceIP == ssh[i].ip_dest_client) && (destPort == ssh[i].port_source_client) && (sourcePort == ssh[i].port_dest_client))
      return i;
    else if((destIP == ssh[i].ip_source_server) && (sourceIP == ssh[i].ip_dest_server) && (destPort == ssh[i].port_source_server) && (sourcePort == ssh[i].port_dest_server))
      return i;
  }
  ncount++;
  return ncount-1;
}


void Split(char *str, int *sum,struct ndpi_flow_struct *flow){
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_char *temp_pointer = (packet->payload + 26); /* 26 byte = 4 byte packet length + 1 byte padding length 
    + 1 byte msg code + 16 byte ssh cookie + 4 kex_algorithms_length */
    for (int i = 0; i < packet->payload_packet_len ; i++) {
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






void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	

  if (flow->l4.tcp.ssh_stage == 0) {
    if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      if(!ndpi_struct->disable_metadata_export) {
        //lui si salva il payload ssh-ubunto(esempio ) in un campo della struttura flow
        //che volendo si possono inserire i campi della nostra struttura ma poi non so come aggragre tutti i 
        // pacchetti che fanno parte della stessa comunicazione
        int len = ndpi_min(sizeof(flow->protos.ssh.client_signature)-1, packet->payload_packet_len);
	strncpy(flow->protos.ssh.client_signature, (const char *)packet->payload, len);
	flow->protos.ssh.client_signature[len] = '\0';
	ndpi_ssh_zap_cr(flow->protos.ssh.client_signature, len);
        /*** estensione */
        int pos = GetPos(packet->iph->saddr, packet->iph->daddr, packet->tcp->source, packet->tcp->dest);
        strncpy(ssh[pos].ssh_protocol_client,(const char *)packet->payload, len);
        ssh[pos].ip_source_client=packet->iph->saddr;
        ssh[pos].port_source_client =  packet->tcp->source;
        ssh[pos].ip_dest_client= packet->iph->daddr;
        ssh[pos].port_dest_client = packet->tcp->dest;
      }
      NDPI_LOG_DBG2(ndpi_struct, "ssh stage 0 passed\n");
      flow->l4.tcp.ssh_stage = 1 + packet->packet_direction;
      return;
    }
  } else if (flow->l4.tcp.ssh_stage == (2 - packet->packet_direction)) {
    if (packet->payload_packet_len > 7 && packet->payload_packet_len < 500
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      if(!ndpi_struct->disable_metadata_export) {
	int len = ndpi_min(sizeof(flow->protos.ssh.server_signature)-1, packet->payload_packet_len);
	strncpy(flow->protos.ssh.server_signature, (const char *)packet->payload, len);
	flow->protos.ssh.server_signature[len] = '\0';
	ndpi_ssh_zap_cr(flow->protos.ssh.server_signature, len);

        int pos = GetPos(packet->iph->saddr, packet->iph->daddr, packet->tcp->source, packet->tcp->dest);
        strncpy(ssh[pos].ssh_protocol_server,(const char *)packet->payload, len);
	ssh[pos].ip_source_server=packet->iph->saddr;
        ssh[pos].port_source_server =  packet->tcp->source;
        ssh[pos].ip_dest_server= packet->iph->daddr;
        ssh[pos].port_dest_server = packet->tcp->dest;
       
      }
      
     NDPI_LOG_INFO(ndpi_struct, "found ssh\n");
     ndpi_int_ssh_add_connection(ndpi_struct, flow);
     return;
    }
  }else if(packet->payload_packet_len > 300 && packet->payload_packet_len < 2000){
      u_int8_t msgcode = *(packet->payload + 5);
      //printf("\nmsg: %u\n",msgcode);
      if(msgcode == 20){
        char *split = calloc(packet->payload_packet_len,sizeof(char));
        int split_counter = 0;
        Split(split, &split_counter,flow);
        if(packet->tcp->dest == 22 || packet->tcp->dest == 2222){
          int pos = GetPos(packet->iph->saddr, packet->iph->daddr, packet->tcp->source, packet->tcp->dest);
          Concat_Algorithms(ssh[pos].algorithms_client, split, split_counter);
          free(split);
          MD5_CTX ctx;
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ssh[pos].algorithms_client, strlen(ssh[pos].algorithms_client));
          MD5Final(ssh[pos].fingerprint_client, &ctx);
          ssh[pos].completed++;
        }
        else {
          int pos = GetPos(packet->iph->saddr, packet->iph->daddr, packet->tcp->source, packet->tcp->dest);
          Concat_Algorithms(ssh[pos].algorithms_server, split, split_counter);
          free(split);
          MD5_CTX ctx;
          MD5Init(&ctx);
          MD5Update(&ctx, (const unsigned char *)ssh[pos].algorithms_server, strlen(ssh[pos].algorithms_server));
          MD5Final(ssh[pos].fingerprint_server, &ctx);
          ssh[pos].completed++;
       }
    }
  } 
   
  NDPI_LOG_DBG(ndpi_struct, "excluding ssh at stage %d\n", flow->l4.tcp.ssh_stage);
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSH);
}


void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SSH", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SSH,
				      ndpi_search_ssh_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

 void PrintInfo(){
    for(int i=0;i<ncount;i++){
      if(ssh[i].completed>1){
        struct in_addr ip_addr_c;
        struct in_addr ip_addr_s;
        
        printf("[-] Client SSH_MSG_KEXINT detected ");
        ip_addr_c.s_addr=ssh[i].ip_source_client;
        ip_addr_s.s_addr=ssh[i].ip_dest_client;
       
	      printf("[%s:%u -> %s:%u]\n",inet_ntoa(ip_addr_c),htonl(ssh[i].port_source_client),inet_ntoa(ip_addr_s),htonl(ssh[i].port_dest_client));
        printf("[-] SSH Protocol: %s",ssh[i].ssh_protocol_client);
        printf("[-] hassh: ");
        for(int j=0; j<16; j++)
          printf("%02x", ssh[i].fingerprint_client[j]);
        printf("\n[-] hassh Algorithms: %s\n",ssh[i].algorithms_client);
        printf("\n[-] Server SSH_MSG_KEXINT detected ");
        ip_addr_c.s_addr=ssh[i].ip_source_server;
        ip_addr_s.s_addr=ssh[i].ip_dest_server;
       
        printf("[%s:%u -> %s:%u]\n",inet_ntoa(ip_addr_c),htonl(ssh[i].port_source_server),inet_ntoa(ip_addr_s),htonl(ssh[i].port_dest_server));
        printf("[-] SSH Protocol: %s",ssh[i].ssh_protocol_server);
        printf("[-] hassh: ");
        for(int j=0; j<16; j++)
          printf("%02x", ssh[i].fingerprint_server[j]);
        printf("\n[-] hassh Algorithms: %s\n\n",ssh[i].algorithms_server);
        for(int i=0;i<80;i++)
          printf("-");
        printf("\n\n");
      }
    }
  }


