#include <limits.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include "hash.h"

#define BITS_IN_int     ( sizeof(int) * CHAR_BIT )
#define THREE_QUARTERS  ((int) ((BITS_IN_int * 3) / 4))
#define ONE_EIGHTH      ((int) (BITS_IN_int / 8))
#define HIGH_BITS       ( ~((unsigned int)(~0) >> ONE_EIGHTH ))

#define HASHTOT 1024 //Dimensione della tabella Hash

#define CHECK_PTR_HASH(X, str)	\
    if ((X)==NULL) {		\
	perror(#str);		\
	exit(EXIT_FAILURE);	\
    } 


SSH **ssh;//Nome della tabella Hash

//Inizializza la tabella Hash 
void InitHash(){
  CHECK_PTR_HASH(ssh=(SSH **)malloc((HASHTOT)*sizeof(SSH *)),Hash.Init);
  for(int i=0;i<HASHTOT;i++){ssh[i]=NULL;}  
} 

//calcolo chiave hash . Fornita dal docente icl_hash.
unsigned int hash_Info(void* key){
  char *datum = (char *)key;
  unsigned int hash_value, i;
  if(!datum) return 0;
  for (hash_value = 0; *datum; ++datum) {
    hash_value = (hash_value << ONE_EIGHTH) + *datum;
    if ((i = hash_value & HIGH_BITS) != 0)
    hash_value = (hash_value ^ (i >> THREE_QUARTERS)) & ~HIGH_BITS;
  }
  return (hash_value)%HASHTOT;
}

//Inserisce l'elemento nella tabella Hash 
SSH* InsertHash(char *sourceIP, char *destIP, int sourcePort, int destPort){
  int i1=hash_Info(sourceIP);//calcolo l'hash
  int i2=hash_Info(destIP);//calcolo l'hash
  char s[255];
  sprintf(s,"%d",sourcePort);
  int i3=hash_Info(s);//calcolo l'hash
  char s1[255];
  sprintf(s1,"%d",destPort);
  int i4=hash_Info(s1);//calcolo l'hash
  int i=(i1+i2+i3+i4)%HASHTOT;
  if(ssh[i]==NULL){//Nel caso non ci sono collisioni: inserisco creo un nuovo utente x
    SSH *new;
    CHECK_PTR_HASH(new=(SSH *)malloc(sizeof(SSH)),Hash.Inserisci);
    new->completed=0;
    new->next=NULL;
    ssh[i]=new;
    return ssh[i];
  }
  //se ho collisioni, devo controllare che l'utente non sia già stato inserito
  SSH *ptr=ssh[i];
  while(ptr!=NULL){
    if(!strcmp(destIP,ptr->ip_source_client) && !strcmp(sourceIP,ptr->ip_dest_client) && destPort==ptr->port_source_client && sourcePort==ptr->port_dest_client)
      return ptr;
    else if(!strcmp(destIP,ptr->ip_source_server) && !strcmp(sourceIP,ptr->ip_dest_server) && destPort==ptr->port_source_server && sourcePort==ptr->port_dest_server)
      return ptr;
    ptr=ptr->next;
  }
  SSH *new;
  CHECK_PTR_HASH(new=(SSH *)malloc(sizeof(SSH)),Hash.Inserisci.trovato);
  new->next=ssh[i];
  new->completed=0;
  ssh[i]=new;
  return ssh[i];
}

//ricerca l'elemento nella tabella hash restituendo il suo puntatore 
SSH*  FindPositionHash(char *sourceIP, char *destIP, int sourcePort, int destPort){
  int i1=hash_Info(sourceIP);//calcolo l'hash
  int i2=hash_Info(destIP);//calcolo l'hash
  char s[255];
  sprintf(s,"%d",sourcePort);
  int i3=hash_Info(s);//calcolo l'hash
  char s1[255];
  sprintf(s1,"%d",destPort);
  int i4=hash_Info(s1);//calcolo l'hash
  int i=(i1+i2+i3+i4)%HASHTOT;
  SSH *ptr=ssh[i];
  //Ricerco nella lista di trabocco se è presente il nick
  while(ptr!=NULL){
    if(!strcmp(destIP,ptr->ip_source_client) && !strcmp(sourceIP,ptr->ip_dest_client) && destPort==ptr->port_source_client && sourcePort==ptr->port_dest_client)
      return ptr;
    else if(!strcmp(destIP,ptr->ip_source_server) && !strcmp(sourceIP,ptr->ip_dest_server) && destPort==ptr->port_source_server && sourcePort==ptr->port_dest_server)
      return ptr;
    ptr=ptr->next;
  }
  SSH *new_ptr=InsertHash(sourceIP, destIP,sourcePort, destPort);
  return new_ptr;
}

//Dealloca l'intera tabella Hash al momento della terminazione del server 
void DestroyHash(){
 SSH *prev=NULL;SSH *ptr=NULL;int i=0;SSH *old=ptr;
 for(;i<HASHTOT;i++){ 
    ptr=ssh[i];prev=NULL;old=ptr;
    while(old!=NULL){
      prev=ptr->next;
      free(ptr);
      old=prev;
      ptr=prev;
    }
  }
  free(ssh);
}
