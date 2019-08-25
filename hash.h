 
typedef struct _nodo{
  struct _nodo *next;
  char ssh_protocol_client[100];
    char algorithms_client[2000];
    u_char fingerprint_client[16];
    char ip_source_client[INET_ADDRSTRLEN];
    char ip_dest_client[INET_ADDRSTRLEN];
    int port_source_client;
    int port_dest_client;
    char ssh_protocol_server[100];
    char algorithms_server[2000];
    u_char fingerprint_server[16];
    char ip_source_server[INET_ADDRSTRLEN];
    char ip_dest_server[INET_ADDRSTRLEN];
    int port_source_server;
    int port_dest_server;
    int completed;
  
}SSH;


  //Inizializza la tabella Hash 
  void InitHash();
 

  //Inserisce l'elemento nella tabella Hash 
  SSH* InsertHash(char *sourceIP, char *destIP, int sourcePort, int destPort);

  //ricerca l'elemento nella tabella hash restituendo il suo puntatore 
  SSH*  FindPositionHash(char *sourceIP, char *destIP, int sourcePort, int destPort);

  //Dealloca l'intera tabella Hash al momento della terminazione del server 
  void DestroyHash();


  //brief calcolo chiave hash 
  unsigned int hash_Info(void* key);
