
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "server.h"
#include "circ_queue.h"
#include "fpga.h"

pcap_t *handle;    /* packet capture handle */
FILE *fptr;
u_char *pkt_data = NULL;    /* packet data including the link-layer header */
struct circ_queue * reque;
int bsdone_queue[100];
#define header_size 1078
#define image_size (512*512)

unsigned int gDATA[512*514];  //Buffer to hold the send data

int main(int argc, char **argv)
{

 char *dev = "eth0";   /* capture device name */
 char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
 char filter_exp[] = "host 169.254.77.77";  /* filter expression */
 struct bpf_program fp;   /* compiled filter program (expression) */
 bpf_u_int32 mask;   /* subnet mask */
 bpf_u_int32 net;   /* ip */
 int num_packets ;   /* number of packets to capture */
 net = 0;
 mask = 0;
 int rtn;
 pthread_t rxthread;
 pthread_t txthread;
 /* open capture device */
 handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
 if (handle == NULL) {
  fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  exit(EXIT_FAILURE);
 }
 /* make sure we're capturing on an Ethernet device [2] */
 if (pcap_datalink(handle) != DLT_EN10MB) {
  fprintf(stderr, "%s is not an Ethernet\n", dev);
  exit(EXIT_FAILURE);
 }
 /* compile the filter expression */
 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
  fprintf(stderr, "Couldn't parse filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
  exit(EXIT_FAILURE);
 }
 /* apply the compiled filter */
 if (pcap_setfilter(handle, &fp) == -1) {
  fprintf(stderr, "Couldn't install filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
  exit(EXIT_FAILURE);
 }
 //Create the circular queue
 reque = init_circ_queue(100);
 if(reque == NULL)
     printf("Failed to create the queue\n");

 rtn= pthread_create(&rxthread, NULL,recv_loop,NULL);
 if (rtn)
 {
     printf("ERROR; return code from pthread_create() is %d\n", rtn);
     return;
 }

 rtn= pthread_create(&txthread, NULL,transmit_loop,NULL);
 if (rtn)
 {
     printf("ERROR; return code from pthread_create() is %d\n", rtn);
     return;
 }

 pthread_join(rxthread, NULL);
 pthread_join(txthread, NULL);

 /* cleanup */
 fclose(fptr);
 pcap_freecode(&fp);
 pcap_close(handle);

return 0;
}


/*
 * dissect/print packet
 */
void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
 
 /* declare pointers to packet headers */
 const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
 const struct sniff_ip *ip;              /* The IP header */
 const char *payload;                    /* Packet payload */
 int size_ip;
 int size_payload;
 int rtn;
 int status;
 static int process_state =0;
 static int pkt_size=0;
 static int proccess_no = 0;
 char command[100];

 /* define ethernet header */
 ethernet = (struct sniff_ethernet*)(packet);
 
 /* define/compute ip header offset */
 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
 size_ip = IP_HL(ip)*4;
 if (size_ip < 20) {
  printf("   * Invalid IP header length: %u bytes\n", size_ip);
  return;
 }
  
 /* define ip payload (segment)*/
 payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
 
 /* compute tcp payload (segment) size */
 size_payload = ntohs(ip->ip_len) - size_ip;
 
 if (size_payload > 0) {
    if(strcmp((char *)payload,"REQ_CONFIG") == 0)
    {
      #ifdef DEBUG
          printf("Configuration request received\n");
      #endif
      rtn = push_circ_queue(reque,proccess_no);
      if(rtn == 1) {
        printf("Error queue is full\n");
        send_packets("eth0", "packets/nak.pcap");
        return;
      }
      else{
         fptr = fopen("bitfile.bin","wb");
      }
    }   
    else if(strcmp((char *)payload,"BS_DONE") == 0)
    {
        #ifdef DEBUG
        printf("Configuration data received\n");
        #endif
        fclose(fptr);
        process_state = 1;
        fptr = fopen("code.c","wb");
        rtn = config_fpga("bitfile.bin");
        if(rtn !=0){
            printf("FPGA reconfiguration failed");
            exit(0);
        }
    } 
    else if(strcmp((char *)payload,"CODE_DONE") == 0)
    {
        #ifdef DEBUG
            printf("Software code received\n");
        #endif
        fclose(fptr);
        process_state = 2;
        fptr = fopen("indata.bin","wb");
        sprintf (command, "gcc fpga.c %s -o %s","code.c","process");
        status = system(command);
        rtn = WEXITSTATUS(status);
        if(rtn != 0){
            printf("Code compilation failed\n");
            return;
        }
    } 
    else if(strcmp((char *)payload,"DATA_DONE") == 0)
    {
        #ifdef DEBUG
            printf("Input data received\n");
        #endif
        fclose(fptr);
        process_state = 3;
        sprintf (command, "./process %s %s","indata.bin","outdata.bin");
        status = system(command);
        rtn = WEXITSTATUS(status);
        if(rtn != 0){
            printf("Execution failed\n");
            return;
        }
        else
            system("python scripts/pktgen.py 0 outdata.bin data.pcap");
    }
    else if(strcmp((char *)payload,"DATA_REQ")==0)
    {
        #ifdef DEBUG
            printf("Data request received\n");
        #endif
        send_packets("eth0", "data.pcap");
        send_packets("eth0", "packets/data_done_ack.pcap");
    }
    else
    {
        fwrite((char *)payload,1,size_payload,fptr);
        //if (process_state == 1){
        //  printf("Packet no %d\n",pkt_size);
        //  pkt_size++;
        //}
    }
 }
 return;
}


void send_packets(char *device, char *trace_file)
{
    FILE *fp; /* file pointer to trace file */
    struct pcap_file_header preamble;
    struct pcap_sf_pkthdr header;
    int pkt_len; /* packet length to send */
    int ret;
    int i;

    if ((fp = fopen(trace_file, "rb")) == NULL)
        printf("fopen(): error reading trace file\n");

    // preamble occupies the first 24 bytes of a trace file
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        printf("fread(): error reading trace_file\n");
    if (preamble.magic != PCAP_MAGIC)
        error("Not a valid pcap based trace file");

    pkt_data = (u_char *)malloc(sizeof(u_char) * ETHER_MAX_LEN);
    if (pkt_data == NULL)
         error("malloc(): cannot allocate memory for pkt_data");
    memset(pkt_data, 0, ETHER_MAX_LEN);
    while ((ret = fread(&header, sizeof(header), 1, fp))) {
        if (ret == 0)
            printf("fread1(): error reading trace_file");

        pkt_len = header.len;

        for (i = 0; i < pkt_len; i++) {
            // copy captured packet data starting from link-layer header 
            if (i < header.caplen) {
                if ((ret = fgetc(fp)) == EOF)
                    printf("fgetc(): error reading trace_file");
                pkt_data[i] = ret;
            }
            else
                // pad trailing bytes with zeros 
                pkt_data[i] = PKT_PAD;
        }
        // move file pointer to the end of this packet data 
        if (i < header.caplen) {
            if (fseek(fp, header.caplen - pkt_len, SEEK_CUR) != 0)
                printf("fseek(): error reading trace_file");
        }
        // finish the injection and verbose output before we give way to SIGINT 
        if (pcap_sendpacket(handle, pkt_data, pkt_len) == -1) {
            printf("%s", pcap_geterr(handle));
        } 
    }
    #ifdef DEBUG
        printf("Data sending Success\n");
    #endif
    free(pkt_data);
    (void)fclose(fp);
}

void * recv_loop()
{
 while(1){
   /* now we can set our callback function */
   pcap_loop(handle, 1 , get_packet, NULL);
 }
}

void * transmit_loop()
{
  int rcv_pkt;
  int rtn;
  while(1){
    //check any data in the request buffer
    rtn = pop_circ_queue(reque,&rcv_pkt);
    if(rtn == 0){
       #ifdef DEBUG
           printf("Request in the queue\n"); 
       #endif
       send_packets("eth0", "packets/ack.pcap");
     }
     else
         ;
  }
}

int config_fpga(char * partial_file)
{
   FILE *prfile;
   char *buffer;
   unsigned long fileLen;
   int rtn;
   prfile = fopen(partial_file, "rb");
   if (!prfile)
   {
      fprintf(stderr, "Unable to open partial bit file\n");
      return -1;
   }
   //Get file length
   fseek(prfile, 0, SEEK_END);
   fileLen=ftell(prfile);
   fseek(prfile, 0, SEEK_SET);
   //Allocate memory
   buffer=(char *)malloc(fileLen+1);
   if (!buffer)
   {
       fprintf(stderr, "Memory error!\n");
       fclose(prfile);
       return -1;
   }
   //Read file contents into buffer
   fread(buffer, 1, fileLen, prfile);
   fclose(prfile);
   //Send partial bitstream to FPGA
   rtn = fpga_send_data(ICAP, (unsigned char *) buffer, fileLen, 0);
   return 0;
}
