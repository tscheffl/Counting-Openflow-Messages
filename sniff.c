/*
Copyright (c) 2016, Thomas Scheffler, Beuth-Hochschule fuer Technik, Berlin, Germany
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
* Neither the name of the copyright holder nor the
  names of its contributors may be used to endorse or promote products
  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "sniff.h"


#define SIZE_ETHERNET 14
#define TRUE 1
#define FALSE 0

#define PACKET_INTERVAL 0.01


int main(int argc, char **argv) 
{
   
   pcap_t *fp;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct pcap_pkthdr *pcap_header;
   const u_char *pkt_data;

   char *ch_ptr;                          /* for time format conversion*/
   char char_buff[20];                    /* for time format conversion*/
   
   int i=0;
   int res;
   int packet_nr = 1;
   int ofMessageCounter_10 = 0;
   int ofMessageCounter_13 = 0;
   int ofMessageCounter_10_total = 0;
   int ofMessageCounter_13_total = 0;
   double firstPacketTime, thisPacketTime, lastPacketTime;
   char morePacketsFlag = 0;
   
   FILE *out_fp; /* File pointer for CSV file */
   char file_name[]="of_message_stats.csv";
   
   
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip;             /* The IP header */
	const struct sniff_tcp *tcp;           /* The TCP header */
	const struct sniff_of *of;             /* The OpenFlow header*/
	u_char *payload; /* Packet payload */
   int offset = 0; /*Difference between Openflow Packet Size and encap. IP Packet*/
   
   
	u_int size_ip;
	u_int size_tcp;
   
   
   if(argc != 2)
   {
      printf("Call program with a pcap-file:\n\t %s filename.pcap\n", argv[0]);
      return EXIT_FAILURE;
   }
   
   /* Open a capture file */
   if ( (fp = pcap_open_offline(argv[1], errbuf) ) == NULL)
   {
      fprintf(stderr,"\nError opening pcap-capture file: %s\n",errbuf);
      return -1;
   }
   
   /* Open the output-file */
   out_fp = fopen(file_name,"w+"); /* (over)write mode */
   if( out_fp == NULL )
   {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
   }
   
   
   /* Retrieve the packets from the file */
   while((res = pcap_next_ex( fp, &pcap_header, &pkt_data)) >= 0)
   {
      /* print pkt timestamp and pkt len */
      printf("%i: %ld:%i (%i)\n", packet_nr, pcap_header->ts.tv_sec, pcap_header->ts.tv_usec, pcap_header->len);          
      if (packet_nr == 1) {
         firstPacketTime = pcap_header->ts.tv_sec + (pcap_header->ts.tv_usec * 0.000001);
         lastPacketTime = firstPacketTime;
      }
      
      ethernet = (struct sniff_ethernet*)(pkt_data);
      ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
	   size_ip = IP_HL(ip)*4;
	   if (size_ip < 20) 
	   {
		   printf("   * Invalid IP header length: %u bytes\n", size_ip);
         return EXIT_FAILURE;
	   }
	   tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
	   size_tcp = TH_OFF(tcp)*4;
	   if (size_tcp < 20) {
		   printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		   return EXIT_FAILURE;
	   }
	   
	   payload = (u_char *)(pkt_data + SIZE_ETHERNET + size_ip + size_tcp);
      of = (struct sniff_of*) (payload + offset);
      

      printf("TCP-SourcePort: %i\n",ntohs(tcp->th_sport));
      printf("TCP-DestinationPort: %i\n",ntohs(tcp->th_dport));
      
      printf("OF-Type: %i\n",of->of_type);
      printf("OF-Length: %i\n",ntohs(of->of_length));
      
      
      /* write OF statistics to file
       * Format: Time in Millisecond since first Packet; Counter Packet_IN messages; Counter Packet_OUT messages 
       */
      
      thisPacketTime = pcap_header->ts.tv_sec + (pcap_header->ts.tv_usec * 0.000001);
      
      if ((thisPacketTime - lastPacketTime) > PACKET_INTERVAL) 
      {
         sprintf(char_buff, "%.6f",lastPacketTime - firstPacketTime);

         /* uncomment following code to substitute  decimal point for decimal comma 
          * in order to be useable in German EXCEL
          */
/*          
         ch_ptr= strstr(char_buff, ".");
         if(ch_ptr != NULL) 
         {
            *ch_ptr = ',';
         }
*/         
         fprintf(out_fp,"%s\t%i\t%i\n", char_buff, ofMessageCounter_10, ofMessageCounter_13);
         
         ofMessageCounter_10 = 0;
         ofMessageCounter_13 = 0;
         lastPacketTime = thisPacketTime;
         morePacketsFlag = FALSE;
      }
      else 
      {
         morePacketsFlag = TRUE;
      }
      
      
      
      /* Count the OF-Messages per Packet */
      if (of->of_type == 10) 
      {   
         ofMessageCounter_10++;
         ofMessageCounter_10_total++;
      }   
      else 
      {
         ofMessageCounter_13++;
         ofMessageCounter_13_total++;
      }
         
      offset = offset + (ntohs(of->of_length) + SIZE_ETHERNET + size_ip + size_tcp) - pcap_header->caplen; 
		
		/*if IP packet contains multiple OF-Messages*/
		while (offset < 0)
		{
			offset = offset + pcap_header->caplen - SIZE_ETHERNET - size_ip - size_tcp;
			of = (struct sniff_of*) (payload + offset);	
			printf("Packet contains another OF-Message at %i: \n",offset);
			printf("OF-Type: %i\n",of->of_type);
			printf("OF-Length: %i\n",ntohs(of->of_length));
         
         
         /* Count the OF-Messages per Packet */

			if (of->of_type == 10) 
         {   
            ofMessageCounter_10++;
            ofMessageCounter_10_total++;
         }   
         else 
         {
            ofMessageCounter_13++;
            ofMessageCounter_13_total++;
         }
			
			offset = offset + (ntohs(of->of_length) + SIZE_ETHERNET + size_ip + size_tcp) - pcap_header->caplen;
         //			offset = offset + ntohs(of->of_length) - pcap_header->caplen ;
		}
		
      printf("Offset: %i\n",offset);
      
     
      printf("\n\n"); 
      packet_nr++;
   }
   
   
   /* Finally */
   if (morePacketsFlag == TRUE) 
   {
      sprintf(char_buff, "%.6f",lastPacketTime - firstPacketTime);
      
      /* uncomment following code to substitute  decimal point for decimal comma 
       * in order to be useable in German EXCEL
       */
      /*          
       ch_ptr= strstr(char_buff, ".");
       if(ch_ptr != NULL) 
       {
       *ch_ptr = ',';
       }
       */             
    
      fprintf(out_fp,"%s\t%i\t%i\n", char_buff, ofMessageCounter_10, ofMessageCounter_13);
   }

     fprintf(out_fp,"\n\n\t\t%s\t%s\n", "IN", "OUT");
     fprintf(out_fp,"\t\t%i\t%i\n", ofMessageCounter_10_total, ofMessageCounter_13_total);
   fclose(out_fp);
   
   if(res == -1)
   {
      printf("Error reading the packets: %s\n", pcap_geterr(fp));
   }
   
   return EXIT_SUCCESS;
}

