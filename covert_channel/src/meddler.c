#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>
#include <string.h>
#include <stdlib.h>
#include "ieee802_11_radio.h"
#include "header.h"
#include "config.h"
#include "link_list.h"
#include "cryptozis.h"

static int  modulo=-1;
static int g_pkt_send=0;
static int g_pkt_recv=0;
static int g_key_received=0;
static int g_key_sent=0;
static int key_flag=1;
static int key_ack_over=0;
int debug=0;
char mode;

u_int16_t response_offset=121;
u_int16_t expected_ack_seq=29;

#define FFSHORT_SIZE 16
#define OFFSET_RATE 0x11
#define FREQ 1
#define MTU_SIZE 124
int nRateIndex=0;

static const u8 u8aRatesToUse[] = {

  54*2,
  48*2,
  36*2,
  24*2,
  18*2,
  12*2,
  9*2,
  11*2,
  11, // 5.5
  2*2,
        1*2
};

int static cnt=0;
u_int32_t total_byte=0;
u_int32_t total_covert_mesg_byte=0;
struct timeval first_pkt_time;
struct timeval last_pkt_time;
int global_counter =0;

static int list_size =0;

/* Original radiotap header for injection
static const u8 u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version
  0x19, 0x00, // <- radiotap header length
  0x6f, 0x08, 0x00, 0x00, // <-- bitmap
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
  0x00, // <-- flags (Offset +0x10)
  0x6c, // <-- rate (0ffset +0x11)
  0x71, 0x09, 0xc0, 0x00, // <-- channel
  0xde, // <-- antsignal
  0x00, // <-- antnoise
  0x01, // <-- antenna

};*/
static const u8 u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version
  0x0d, 0x00, // <- radiotap header length
  0x04, 0x08, 0x20, 0x00, // <-- bitmap
//  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
//  0x00, // <-- flags (Offset +0x10)
  0x60, // <-- rate (0ffset +0x11)
  0x71, 0x00, 0x00, 0x00, // <-- channel

};



u8 u8aIeeeHeader[] = {
  0x08, 0x01, 0x00, 0x00,  //data frame
  //0x08, 0x01, 0x00, 0x00, beacon
  //0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, //bssid mac
  0x13, 0x11, 0x33, 0x44, 0x55, 0x66, //source mac
  0x13, 0x11, 0x33, 0x44, 0x55, 0x66, //destination mac
  0x10, 0x86, //sequence no.
};

char errbuf[PCAP_ERRBUF_SIZE];
config_ config;

int packet_parse(const unsigned char *, struct timeval, unsigned int pkt_len);
u_int32_t covert_message_offset(u_int32_t ack,u_int32_t seq, unsigned int pkt_len);
int message_injection(const unsigned char * packet, u_int16_t radiotap_len, u_int32_t capture_len);
int message_reception(const unsigned char * packet, u_int16_t radiotap_len,u_int32_t capture_len);
int transmit_on_wifi(pcap_t*,u_char *,int);
int tun_allocation(char *);

int tun_allocation(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);

    return fd;
}

pcap_t * pcap_radiotap_handler(char * monitor_interface)
{
  pcap_t *pcap;
  pcap=pcap_open_live(monitor_interface, 1536 , 1,20, errbuf);//check the timeout value 
  if( pcap == NULL)
    {
      fprintf(stderr, "error reading pcap file: %s\n", errbuf);
      exit(1);
    }
/*
  switch (pcap_datalink(pcap)) {
  case DLT_IEEE802_11_RADIO:
    printf("radiotap data link type\n");
    break;
  default:
    printf("wrong data link type\n");
    return NULL;
  }
*/
  return pcap;
}

int transmit_on_wifi(pcap_t* pd, 
		     u_char* fr_to_tx,
		     int pkt_len)
{
  u_int32_t r;
  struct ieee80211_radiotap_header * hdr; 
  hdr = (struct ieee80211_radiotap_header *)fr_to_tx;
  //int idx=0;
  //for (idx=0;idx<pkt_len;idx++)
  //printf("%02x ",fr_to_tx[idx]);
  //printf("%02x %02x %02x %02x \n",*fr_to_tx, *(fr_to_tx+1), *(fr_to_tx+2),*(fr_to_tx+3));
  r = pcap_inject(pd, fr_to_tx, pkt_len);
  if (r != (pkt_len)){
    perror("Trouble injecting packet");
    return -1;
  }
  return 0;
}

u_int32_t covert_message_offset(u_int32_t seq,u_int32_t ack, u_int32_t pkt_len)
{
  //have to use the shared key of the session to produce this number again!
  u_int32_t offset=0; 
  u_int32_t temp=0;
  temp=ack+5*seq;
  u_char*str = (u_char*)&temp;
  int c;
  int i=0;
  unsigned long hash = 5676; //encoding of shared key f=f^ord(a[i])
  for(i=0;i<4;i++){
     c=str[i];
     hash= ((hash<< 5) +hash) +c;

  }
  offset=hash %(pkt_len-MTU_SIZE);
  //printf("offset=%d\n",offset);
  return offset ;
}


/*
  The function reads the corrupted frames to see if the frame
  contains the covert message. Strips of the initial bytes to
  get the tun frame that should be written to the tun descriptor

*/
int message_reception(const unsigned char * packet, 
		      u_int16_t radiotap_len,
		      u_int32_t capture_len)
{
 //printf("this is message reception\n");
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc, covert_msg_size=0 ;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len-4;
  u_int32_t pkt_len_1=capture_len-4 -radiotap_len;
  int tcp_options =TCP_OPTIONS; //TCP options
  int bytes_written=0;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  //printf("mac hdr len=%d\n",mac_hdr_len);
  packet +=mac_hdr_len; //TODO: FIXME: Does not work with adding 8 bytes
  capture_len -= mac_hdr_len;
  llc = (struct llc_hdr *) packet;
   //printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection eg. gmail*/
      return -1;
     }
    packet += IP_header_length;
    capture_len -= IP_header_length;
    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    message_offset = covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len_1);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    //printf("message received bef ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2) );

//    if (ssl_h->ssl_content_type != 0x17) {
//printf("not 17\n");
//      return -1; /*there should be content in the traffic*/
//    }

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);

    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes < MTU_SIZE ) {
	    printf("not enough bytes remaining\n");
        return -1; 
    }
    /* TODO:
       use the key to decrypt the length of message following it       
    */
    int return_val=0,tmp_len=16;
    packet +=message_offset;
    // decrypt the message length for reading the following message
    u_char* encrypt_covert_msg_size ;
    encrypt_covert_msg_size=malloc(FFSHORT_SIZE);
    memset(encrypt_covert_msg_size,0,FFSHORT_SIZE);
    u_char* tmp_covert_msg_size;
    memcpy(encrypt_covert_msg_size, packet, FFSHORT_SIZE);
    return_val=decrypt_digest(&config.de, encrypt_covert_msg_size, &tmp_covert_msg_size, (int*)&tmp_len);
    if (return_val <0) {
	printf("Couldn't decrypt msg len\n");
	return -1;
    }
    u_int32_t ttt=0;
    memcpy((u_char*)&ttt,tmp_covert_msg_size,4);
    covert_msg_size=ttt;
    printf("after decrypt= %u tmp_len=%d\n",covert_msg_size,tmp_len);
    	
    packet +=FFSHORT_SIZE;
    u_char* hmac;
    hmac = malloc((size_t)SHA_SIZE);
    memset(hmac,0,(size_t)SHA_SIZE);
    memcpy(hmac,packet,(size_t)SHA_SIZE);

    packet +=SHA_SIZE;
    //printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));
    u_char* encrypt_msg;
    encrypt_msg = malloc((size_t)covert_msg_size);
    memset(encrypt_msg,0,(size_t)covert_msg_size);
    memcpy(encrypt_msg,packet,(size_t)covert_msg_size);

    u_char* decrypted_tun_frame;
    u_char* sha_decr_frame;
    int decrypted_tun_frame_len=covert_msg_size;
    int frame_len=covert_msg_size;

    sha_decr_frame = HMAC(EVP_sha256(), config.shared_key, config.shared_key_len ,encrypt_msg,frame_len, NULL, NULL);
    if (sha_decr_frame ==NULL) {
      printf("calculated sha is null value");
      return -1;
    }
    if(!memcmp(sha_decr_frame,hmac,SHA_SIZE)) {
    }else {
	printf("sha did not match %d %d\n",covert_msg_size, message_offset);
      return -1;
	}
    return_val =decrypt_digest(&config.de, encrypt_msg, &decrypted_tun_frame, (int*)&decrypted_tun_frame_len);
    if (return_val <0) {
      printf("decr fail ");
      free(hmac);
      free(encrypt_msg);
      return -1;
    }
    //printf("decrypted correctly\n");
    u_char *t =decrypted_tun_frame;
    printf("ip:%02x %02x %02x %02x \n",*t,*(t+1),*(t+2),*(t+3));
    if(!memcmp(sha_decr_frame,hmac,SHA_SIZE)) {
      //printf("ip:%02x %02x %02x %02x \n",*t,*(t+1),*(t+2),*(t+3));
      //printf("correct SHA and shoving to TUN %d\n",decrypted_tun_frame_len);
      if((bytes_written=write(config.tun_fd,decrypted_tun_frame,decrypted_tun_frame_len))<0) {
	perror("Error in writing the message frame to TUN interface\n");
	return -1;
      }
      else {
	printf("packet is written to tun driver yay!\n");
	if (global_counter ==0) {
	  gettimeofday(&first_pkt_time,NULL);
	  gettimeofday(&last_pkt_time,NULL);
	  global_counter=1;
	}else {
	  gettimeofday(&last_pkt_time,NULL);
	}
	total_byte=total_byte+decrypted_tun_frame_len;
	int sec_elapsed;
	int usec_elapsed;
	float total_elapsed;
	sec_elapsed=last_pkt_time.tv_sec-first_pkt_time.tv_sec;
	if (last_pkt_time.tv_sec-first_pkt_time.tv_sec) {
	  sec_elapsed=sec_elapsed-1;
	  usec_elapsed = 1000000LL +last_pkt_time.tv_usec -first_pkt_time.tv_usec;
	}else {
	  usec_elapsed = last_pkt_time.tv_usec -first_pkt_time.tv_usec;
	}
	g_pkt_recv++;
	total_elapsed= sec_elapsed + usec_elapsed/1000000LL;
	printf("cnt=%d orig=%d, t=%f \n",g_pkt_recv, total_byte, total_elapsed);
	printf("usec elapsed =%d\n ", last_pkt_time.tv_usec-first_pkt_time.tv_usec);
      }
    }
    else {
      // printf("SHA of the frame is INcorrect u=%d fl=%d dcr_fl=%d \n",u, frame_len,decrypted_tun_frame_len);
    }
    // printf("freeeing in decrytion\n");
    free(encrypt_msg);
    free(decrypted_tun_frame);
    free(hmac);
  }else {
  //  printf("Error: message reception failed due to offset issue\n");
  }
  cnt++;
  if (cnt%20==0)
    printf("r=%d ",g_pkt_recv);
  
  return 0;
}
/*
  The function is called when a copy of wireless frame transmitted.
*/
static int ppp=0;
int message_injection(const unsigned char * packet,
		      u_int16_t radiotap_len,
		      u_int32_t capture_len)
{
  printf("message_injection()  %d %d %d %d\n",list_size,g_pkt_send,ppp,modulo );
  if (!(list_size>0))
    return -1;
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,seq_no,duration_id,message_len;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len-radiotap_len + sizeof (u8aRadiotapHeader);
  u_int32_t pkt_len_1=capture_len-radiotap_len ;

  u_int32_t frame_tx_idx=0;
  int tcp_options =TCP_OPTIONS;
  const u_char* mac_address_start;
  const u_char* llc_start_p ;
  u_char * temp_pkt=packet;
  u_char * temp_pkt_len=capture_len;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  duration_id= sc->duration_id;
  mac_address_start=(packet+4);
  seq_no=sc->seq_ctrl;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(u_int8_t)(mac_hdr_len);
  capture_len -= mac_hdr_len;
  llc_start_p= packet-2;//2 bytes padding by atheros adapter
  llc = (struct llc_hdr *) (packet/* +8 */ );
  //packet =packet+8;
  u_char* l= (u_char* )llc;
  //printf("llc_start=%02x %02x %02x %02x \n",*l,*(l+1),*(l+2),*(l+3));
  //printf("%d %d\n",ntohs(llc->snap.ether_type),ETHERTYPE_IP);
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection*/
        return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;

    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    tcp_options=((tcp_h->offx2 >> 4) << 2) -sizeof(struct tcp_hdr);
    //printf("tcp options=%d\n",tcp_options);
    message_offset =  covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len_1);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    /*   if (ssl_h->ssl_content_type != 0x17) {
	 printf("not ssl ");
	 return -1; //not SSL traffic
	 }
    */
    //  printf("ssl v= %02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2)  );
    
    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ;
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MTU_SIZE ) {
        printf("not enough bytes remaining\n ");
        return -1; 
    }

    u_char* frame_to_transmit=NULL;
    u_char* start_frame_to_transmit= malloc(pkt_len);
    memset(start_frame_to_transmit,'\0',sizeof(start_frame_to_transmit));
    frame_to_transmit = start_frame_to_transmit;

    u_char* pu8;

    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    pu8 = frame_to_transmit;
    pu8[8] = u8aRatesToUse[nRateIndex];
        nRateIndex=nRateIndex+2;
        if (nRateIndex >=sizeof(u8aRatesToUse))
                nRateIndex=0;
    frame_to_transmit += sizeof (u8aRadiotapHeader);
    frame_tx_idx  += sizeof (u8aRadiotapHeader);

    struct ieee80211_hdr * ih = (struct ieee80211_hdr *) u8aIeeeHeader;
    //fc= fc | BIT(6); // for WEP bit to be turned on
    memcpy((u_char*)(&(ih->frame_control)),(u_char*)&fc,SHORT_SIZE);
    memcpy((u_char*)(&(ih->duration_id)),(u_char*)&duration_id,SHORT_SIZE);
    memcpy(&(ih->addr1),mac_address_start,MAC_HDR);
    memcpy((u_char*)(&(ih->seq_ctrl)),(u_char*)&seq_no,SHORT_SIZE);
    //printf("ntohs seq no=%d\n",ntohs(seq_no));
    //printf("htonl seq no=%d\n",htons(seq_no));
    // memcpy(&(ih->addr2),mac_address_start+MAC_HDR,MAC_HDR); //commented for testing purposes

    //memcpy(&(ih->addr3),mac_address_start+(2*MAC_HDR),MAC_HDR);
    if (debug) {
        printf("packet_injection\n");
        printf("addr1:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr1[0],ih->addr1[1],ih->addr1[2],ih->addr1[3],ih->addr1[4], ih->addr1[5]);
        printf("addr2:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr2[0],ih->addr2[1],ih->addr2[2],ih->addr2[3],ih->addr2[4], ih->addr2[5]);
        printf("addr3:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr3[0],ih->addr3[1],ih->addr3[2],ih->addr3[3],ih->addr3[4], ih->addr3[5]);
    }

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);
    frame_tx_idx += sizeof(u8aIeeeHeader);

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;
    frame_tx_idx += ssl_hdr_end_p-llc_start_p;

    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;
    packet += message_offset;
    frame_tx_idx += message_offset;
    capture_len -= message_offset;

    /*
        Number of messages and the total message length to be added here
    */
    int r;
    u_char *hmac;
    u_char* content;
    r=beg_del_element(&config.tun_f_list,&content, &message_len,&hmac);
    if (r ==-1)
      return;
    list_size--;
    assert(message_len>0);

    u_char* encrypt_msg_len;
    u_char* msg_len; 
    u_int32_t msg_len_32=message_len;
    msg_len = malloc(sizeof(u_int32_t));
    memset(msg_len,'0',sizeof (u_int32_t));
    memcpy(msg_len,(u_char*)&msg_len_32,sizeof(u_int32_t));
    int cipher_msg_len = 4; 
    r=encrypt_digest(&config.en, msg_len, &encrypt_msg_len, &cipher_msg_len);
    if (r < 0) {
           free(msg_len);
           printf("couldn't encrypt msg len\n");   
           return -1;
        }
        //printf("%02x %02x %02x %02x \n", *(encrypt_msg_len),*(encrypt_msg_len+1), *(encrypt_msg_len+2), *(encrypt_msg_len+3));
    memcpy(frame_to_transmit,encrypt_msg_len,FFSHORT_SIZE);
     
    frame_to_transmit +=FFSHORT_SIZE;
    packet += FFSHORT_SIZE;
    frame_tx_idx += FFSHORT_SIZE;
    capture_len -= FFSHORT_SIZE;

    memcpy(frame_to_transmit,hmac,SHA_SIZE);
    frame_to_transmit +=SHA_SIZE;
    packet += SHA_SIZE;
    frame_tx_idx += SHA_SIZE;
    capture_len -= SHA_SIZE;

    memcpy(frame_to_transmit, content,message_len);
    frame_to_transmit +=message_len ;
    packet += message_len;
    frame_tx_idx += message_len;
    capture_len -= message_len;
    free(content);
    free(hmac);

    memcpy(frame_to_transmit,packet,pkt_len_1-frame_tx_idx);
    frame_to_transmit += (pkt_len_1-frame_tx_idx);
    capture_len -= (pkt_len_1-frame_tx_idx);
    if (pkt_len ==capture_len) {
      printf("wrong!");
      exit(1);
    }
    int udx =0;
    printf ("orig frame\n");
    transmit_on_wifi(config.wifi_inject_pcap,start_frame_to_transmit, pkt_len); //frame_to_transmit-start_frame_to_transmit);
    free(msg_len);
    free(start_frame_to_transmit);
  } else {
  printf("injection not happening");
 }
  return 0 ;
}

/*
  key sharing code starts
*/
u_int16_t g_response_offset=0, rcv_exp_ack_seq=0;
/*
The receiver receives the key and parameters in this function.
This should give control to function which transmits the acknowledgement from receiver
*/
int key_reception(const unsigned char * packet,
		  u_int16_t radiotap_len,
		  u_int32_t capture_len)
{
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len-radiotap_len-4;
  int tcp_options =TCP_OPTIONS; //TCP options
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len);

  capture_len -= (mac_hdr_len);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection eg. gmail*/
      printf("key_reception: NOT TCP\n");
      return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;
    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    message_offset = covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    //printf("message received bef ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2) );
    /*
    if (ssl_h->ssl_content_type != 0x17) {
      printf("not SSL traffic\n");
      return -1; 
    }
    */
    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);

    if(remaining_bytes <MTU_SIZE){
      printf("not enough remaining bytes\n");
    //  return -1; /*for now it's mtu=150 bytes*/
    }

    /* TODO:
       use the key to decrypt the length of message following it
    */
    //printf("Start key reception %d\n",message_offset);
    packet +=message_offset;

    u_int32_t message_size =0;
    int encrypt_msg_len = 256;
    int decr_msg_len_len = 1;
    u_char msg_len[1000];
    u_char* encrypt_message_size = malloc(256);
    memset(encrypt_message_size, 0, encrypt_msg_len);
    memcpy(encrypt_message_size, packet, 256);
    //printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));
    decr_msg_len_len = RSA_private_decrypt(encrypt_msg_len, encrypt_message_size, msg_len, config.rcv_priv_key, RSA_PKCS1_PADDING);
    if (decr_msg_len_len ==-1) {
	printf("RSA decryption failed\n");
	return -1;
    }
    memcpy((u_char*)&message_size, msg_len,sizeof(u_int32_t));

    packet +=256;

    u_char* hmac;
    hmac= malloc(SHA_SIZE);
    memset(hmac,0,SHA_SIZE);
    memcpy(hmac,packet,SHA_SIZE);
    packet +=SHA_SIZE;

    u_char* session_key;
    session_key = malloc(message_size);
    memset(session_key,0,message_size);
    memcpy(session_key,packet,message_size);
    packet +=message_size;
    config.encr_shared_key_len=message_size;
    u_char* sha_256;
    sha_256 = HMAC(EVP_sha256(), "Abhinav", strlen("Abhinav"), session_key, (const int)message_size, NULL, NULL);
    if (memcmp(hmac,sha_256,SHA_SIZE))  {
	printf("the sha of the frame do not match! hence not the 'key' frame BAD!!!\n");
	free(hmac);
	free(session_key);
	return -1;
    } else  {
	printf("SHA did MATCH\n");
    }

    memcpy(config.encr_shared_key,session_key, config.encr_shared_key_len);

    if (debug) {
      char* b64String = base64Encode(config.encr_shared_key, config.encr_shared_key_len);
      printf("Encrypted message: %s\n", b64String);
    }

    if((config.decr_shared_key_len = rsa_decrypt()) == -1) {
      fprintf(stderr, "Decryption of key failed\n");
      return -1;
    }

    printf("decr key:%s\n", config.decr_shared_key);
    memcpy(config.shared_key,config.decr_shared_key,config.decr_shared_key_len);
    config.shared_key_len =config.decr_shared_key_len;
    memcpy((u_char*)&g_response_offset, packet,SHORT_SIZE);
    packet += SHORT_SIZE;
    
    memcpy((u_char*)&rcv_exp_ack_seq, packet, SHORT_SIZE);
    packet += SHORT_SIZE;
    if (debug)
    printf("RECEPTION: g_resp_of=%u, rcv_exp_ack=%u\n", g_response_offset, rcv_exp_ack_seq);

    g_key_received=1;
    if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
      printf("Couldn't initialize AES cipher in client \n");
      return -1;
    }else {
      printf("aes initialized with a key on client \n");
    }
    free(hmac);
    free(session_key);
  }else{
   // printf("Error: Due to offset mismatch and L2+ headers from network adapter\n");
  }
  return 0;
}
/*
The transmitter understands that the key transfer is actually over.
It checks the acknowledgement.
*/
int key_ack_finish(const unsigned char * packet,
		   u_int16_t radiotap_len,
		   u_int32_t capture_len)
{
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int16_t message_offset=0;
  u_int16_t message_size =0;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS;
  packet += radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;

  packet +=(mac_hdr_len); 
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection eg. gmail*/
      printf("key_ack_finish: NOT TCP packets \n");
      return -1;
    }
    packet += IP_header_length;
    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    message_offset =  response_offset ; //goto this offset to read 
    packet +=sizeof(struct tcp_hdr);

    packet += tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    //printf("message received bef ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2) );
    /*
    if (ssl_h->ssl_content_type != 0x17) {
      printf("not SSL traffic\n");
      return -1; 
    }
    */
    packet += sizeof(struct ssl_hdr);

    packet +=message_offset;

    u_int32_t message_size=0;
    int encrypt_msg_len =256;
    int decr_msg_len_len=1;
    u_char msg_len[1000];
    u_char* encrypt_message_size = malloc(256);
    memset(encrypt_message_size, 0, encrypt_msg_len);
    memcpy(encrypt_message_size, packet, 256);
    printf("response offset is%d \n",response_offset);

    printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));


    decr_msg_len_len= RSA_private_decrypt(encrypt_msg_len, encrypt_message_size, msg_len, config.rcv_priv_key, RSA_PKCS1_PADDING);
    if(decr_msg_len_len ==-1) {
           printf("KEy ack finish: RSA decryption failed \n");
           return -1;
    }
    printf("done with decryption  %d\n",decr_msg_len_len);
    memcpy((u_char*)&message_size,msg_len,sizeof(u_int32_t));
    packet +=256;

    u_char* hmac;
    hmac= malloc(SHA_SIZE);
    memset(hmac,0,SHA_SIZE);
    memcpy(hmac,packet,SHA_SIZE);
    packet +=SHA_SIZE;

    u_char* session_key;
    session_key = malloc(message_size);
    memset(session_key,0,message_size);
    memcpy(session_key,packet,message_size);

    u_int16_t temp =  (u_int16_t) (*session_key);
    u_char* sha_256;
    printf("ack back is:%u \n",temp);
    sha_256 = HMAC(EVP_sha256(), "Abhinav", strlen("Abhinav"), session_key, (const int)message_size, NULL, NULL);
    if (!memcmp(hmac,sha_256,SHA_SIZE)) {
      printf(" sha is matching for final ACK received\n");
    } else {
      //printf(" NO MATCH final ACK received %u\n",temp);
      free(hmac);
      free(session_key);
      return -1;
    }
    if (temp=expected_ack_seq+1) {
      printf("KEY ACK DONE rcv=%d exp=%d\n", temp, expected_ack_seq);
      key_ack_over=1;
      return 0;
    } else {
      printf("KEY ACK NOT FOUND\n");
      return -1;
    }
  }else {
    // printf("key_ack_finish has bad LLC offset\n");
  }
  return 0;
}
/*
  Injects the shared encrypted session key
*/
int key_injection(const unsigned char * packet,
		  u_int16_t radiotap_len,
		  u_int32_t capture_len)
{
  printf("key_injection()\n");
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,seq_no,duration_id;
  u_int32_t message_offset;
  u_int32_t frame_tx_idx=0;
  u_int32_t pkt_len_1=capture_len-radiotap_len;
  u_int32_t pkt_len=capture_len-radiotap_len+sizeof(u8aRadiotapHeader);

  int tcp_options =TCP_OPTIONS;
  const u_char* mac_address_start;
  const u_char* llc_start_p ;

  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  duration_id= sc->duration_id;
  mac_address_start=(packet+4);
  seq_no=sc->seq_ctrl;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;

  packet +=(mac_hdr_len);
  llc_start_p= packet-2;
  capture_len -= (mac_hdr_len);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection*/
      return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;

    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    tcp_options=((tcp_h->offx2 >> 4) << 2) -sizeof(struct tcp_hdr);
    message_offset =  covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len_1);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    if (ssl_h->ssl_content_type != 0x17) {
      printf("not SSL traffic\n");
      //return -1; 
    }
    printf("ssl v= %02x %02x %02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1), *((u_int8_t*)(ssl_h)+2));

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ;
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
     printf("remaining bytes =%d\n", remaining_bytes); 
   if (remaining_bytes <MTU_SIZE) {
      printf("not enough remaining bytes \n");
      return -1;
    }
    u_char *hmac;
    u_char* frame_to_transmit=NULL;
    u_char* start_frame_to_transmit= malloc(pkt_len);
    memset(start_frame_to_transmit,'\0',sizeof(start_frame_to_transmit));
    frame_to_transmit = start_frame_to_transmit;

    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    frame_to_transmit += sizeof (u8aRadiotapHeader);
    frame_tx_idx  += sizeof (u8aRadiotapHeader);

    struct ieee80211_hdr * ih = (struct ieee80211_hdr *) u8aIeeeHeader;
    //fc= fc | BIT(6); // for WEP bit to be turned on
    memcpy((u_char*)(&(ih->frame_control)),(u_char*)&fc,SHORT_SIZE);
    memcpy((u_char*)(&(ih->duration_id)),(u_char*)&duration_id,SHORT_SIZE);
    memcpy(&(ih->addr1),mac_address_start,MAC_HDR);
    memcpy((u_char*)(&(ih->seq_ctrl)),(u_char*)&seq_no,SHORT_SIZE);
    // memcpy(&(ih->addr2),mac_address_start+MAC_HDR,MAC_HDR); //commented for testing purposes
    //memcpy(&(ih->addr3),mac_address_start+(2*MAC_HDR),MAC_HDR);
    if (debug) {
      printf("packet_injection\n");
      printf("addr1:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr1[0],ih->addr1[1],ih->addr1[2],ih->addr1[3],ih->addr1[4], ih->addr1[5]);
      printf("addr2:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr2[0],ih->addr2[1],ih->addr2[2],ih->addr2[3],ih->addr2[4], ih->addr2[5]);
      printf("addr3:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr3[0],ih->addr3[1],ih->addr3[2],ih->addr3[3],ih->addr3[4], ih->addr3[5]);
    }

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);
    frame_tx_idx += sizeof (u8aIeeeHeader);

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;
    frame_tx_idx += ssl_hdr_end_p-llc_start_p;

    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;
    frame_tx_idx +=message_offset;
    packet += message_offset;
    capture_len -= message_offset;

    u_int32_t message_len;
    message_len = config.encr_shared_key_len; //for 16 bit predecided offset

    u_char encr_message_len[1000];
    u_char* msg_len= malloc(sizeof(message_len));
    memset(msg_len,0,sizeof(message_len));
    memcpy(msg_len,(u_char*)&message_len,sizeof(message_len)); 
    int encr_message_len_len=4;
    int tmp_len= sizeof(message_len);
    encr_message_len_len =RSA_public_encrypt(tmp_len, msg_len, encr_message_len, config.snd_pub_key, RSA_PKCS1_PADDING);
    if (encr_message_len_len <0) { 
         printf("RSA encrypt screwed\n");
         return -1;
      }
    printf("encr_msg_len_len=%d \n",encr_message_len_len);
    free(msg_len);

    u_char* content;
    content = malloc(message_len);
    memset(content,'\0',message_len);
    memcpy(frame_to_transmit,encr_message_len,256);
    frame_to_transmit +=256;
    packet += 256;
    frame_tx_idx += 256;
    capture_len -= 256;


    memcpy(content,(u_char*)config.encr_shared_key, message_len);

    hmac = HMAC(EVP_sha256(), "Abhinav", strlen("Abhinav"), content, (const int)config.encr_shared_key_len, NULL, NULL);
    memcpy(frame_to_transmit,hmac,SHA_SIZE);

    frame_to_transmit +=SHA_SIZE;
    packet += SHA_SIZE;
    frame_tx_idx += SHA_SIZE;
    capture_len -= SHA_SIZE;

    memcpy(frame_to_transmit, content, message_len);
    frame_to_transmit +=message_len;
    packet += message_len;
    frame_tx_idx += message_len;
    capture_len -= message_len;

    printf("response_offset=%u, exp =%u\n", response_offset, expected_ack_seq);
    memcpy(frame_to_transmit,(u_char*)&response_offset, SHORT_SIZE);
    frame_to_transmit += SHORT_SIZE;
    frame_tx_idx += SHORT_SIZE;
    packet += SHORT_SIZE;
    capture_len -= SHORT_SIZE;

    memcpy(frame_to_transmit,(u_char*)&expected_ack_seq, SHORT_SIZE);
    frame_to_transmit += SHORT_SIZE;
    frame_tx_idx += SHORT_SIZE;
    packet += SHORT_SIZE;
    capture_len -= SHORT_SIZE;

    memcpy(frame_to_transmit,packet,pkt_len-frame_tx_idx);
    frame_to_transmit += (pkt_len-frame_tx_idx);
    capture_len -= (pkt_len-frame_tx_idx);
    //while(1){
    printf("KEY TX pkt size diff=%d pkt_len%u cap_len=%d, key_len=%d\n",(frame_to_transmit-start_frame_to_transmit), \
	   pkt_len,capture_len,message_len);
    transmit_on_wifi(config.wifi_inject_pcap,start_frame_to_transmit, pkt_len);
    //}
    g_key_sent=1;
    free(start_frame_to_transmit);
    free(content);
    printf("SESSION KEY TRANSMITTED!! \n");
  }else {
    printf("key injection is not working\n");
  }
  return 0 ;
}

int key_ack_transmit(const unsigned char * packet,
		     u_int16_t radiotap_len,
		     u_int32_t capture_len)
{
  printf("key_ack_transmit() %d\n",capture_len);
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,seq_no,duration_id;
  u_int32_t message_len;
  u_int16_t message_offset;
  u_int32_t frame_tx_idx=0;
  u_int32_t pkt_len=capture_len-radiotap_len+sizeof(u8aRadiotapHeader);
  u_int32_t pkt_len_1=capture_len-radiotap_len;
  int tcp_options =TCP_OPTIONS;
  const u_char* mac_address_start;
  const u_char* llc_start_p ;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  duration_id= sc->duration_id;
  mac_address_start=(packet+4);
  seq_no=sc->seq_ctrl;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;

  packet +=(mac_hdr_len);
  llc_start_p= packet-2;
  capture_len -= (mac_hdr_len);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl*4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection*/
      return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;

    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    tcp_options=((tcp_h->offx2 >> 4) << 2) -sizeof(struct tcp_hdr);
    message_offset =  g_response_offset;
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    if (ssl_h->ssl_content_type != 0x17) {
      printf("not SSL traffic\n");
      //return -1; 
    }
    printf("ssl v= %02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1), *((u_int8_t*)(ssl_h)+2));

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ;
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MTU_SIZE+1) {
	printf("ret back %u %d %d %d %d \n",capture_len,remaining_bytes,MAX_MTU_SIZE, message_offset);
      return -1; /*for now it's mtu=150 bytes*/
    }
    printf("transmitting ack back with expec value \n");
    u_char *hmac;
    u_char* frame_to_transmit=NULL;
    u_char* start_frame_to_transmit= malloc(pkt_len);
    memset(start_frame_to_transmit,'\0',pkt_len);
    frame_to_transmit = start_frame_to_transmit;

    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    frame_to_transmit += sizeof (u8aRadiotapHeader);
    frame_tx_idx += sizeof (u8aRadiotapHeader);

    struct ieee80211_hdr * ih = (struct ieee80211_hdr *) u8aIeeeHeader;
    //fc= fc | BIT(6); // for WEP bit to be turned on
    memcpy((u_char*)(&(ih->frame_control)),(u_char*)&fc,SHORT_SIZE);
    memcpy((u_char*)(&(ih->duration_id)),(u_char*)&duration_id,SHORT_SIZE);
    memcpy(&(ih->addr1),mac_address_start,MAC_HDR);
    memcpy((u_char*)(&(ih->seq_ctrl)),(u_char*)&seq_no,SHORT_SIZE);
    // memcpy(&(ih->addr2),mac_address_start+MAC_HDR,MAC_HDR); //commented for testing purposes
    //memcpy(&(ih->addr3),mac_address_start+(2*MAC_HDR),MAC_HDR);
    if (debug) {
      printf("key_ack_transmit\n");
      printf("addr1:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr1[0],ih->addr1[1],ih->addr1[2],ih->addr1[3],ih->addr1[4], ih->addr1[5]);
      printf("addr2:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr2[0],ih->addr2[1],ih->addr2[2],ih->addr2[3],ih->addr2[4], ih->addr2[5]);
      printf("addr3:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr3[0],ih->addr3[1],ih->addr3[2],ih->addr3[3],ih->addr3[4], ih->addr3[5]);
    }

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);
    frame_tx_idx += sizeof (u8aIeeeHeader);

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;
    frame_tx_idx += ssl_hdr_end_p-llc_start_p;

    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;
    frame_tx_idx +=message_offset;
    packet += message_offset;
    capture_len -= message_offset;

    message_len = 2; 
    u_char encr_message_len[1000];
    u_char* msg_len= malloc(sizeof(message_len));
    memset(msg_len,0,sizeof(message_len));
    memcpy(msg_len,(u_char*)&message_len,sizeof(message_len));
    int encr_message_len_len =4;
    int tmp_len = sizeof(message_len);
    encr_message_len_len = RSA_public_encrypt(tmp_len, msg_len, encr_message_len, config.snd_pub_key, RSA_PKCS1_PADDING);
    if(encr_message_len_len <0) {
	printf("RSA encrypt screwed\n");
	return -1;
    }
    printf("encr_msg_len_len=%d\n",encr_message_len_len);
    free(msg_len);

    u_char* content;
    content = malloc(message_len);
    memset(content,'\0',message_len);

    memcpy(frame_to_transmit,encr_message_len, 256);
    frame_to_transmit +=256;
    frame_tx_idx +=256;
    packet += 256;
    capture_len -= 256;

    u_int16_t temp = rcv_exp_ack_seq+1; //increment the seq
    memcpy(content,(u_char*)&temp, SHORT_SIZE);

    hmac = HMAC(EVP_sha256(), "Abhinav", strlen("Abhinav"),content ,(const int)message_len, NULL, NULL);
    memcpy(frame_to_transmit,hmac,SHA_SIZE);

    frame_to_transmit +=SHA_SIZE;
    frame_tx_idx +=SHA_SIZE;
    packet += SHA_SIZE;
    capture_len -= SHA_SIZE;

    memcpy(frame_to_transmit, content, message_len);
    frame_to_transmit +=message_len;
    frame_tx_idx +=message_len;
    packet += message_len;
    capture_len -= message_len;

    memcpy(frame_to_transmit,packet,pkt_len_1-frame_tx_idx);
    frame_to_transmit += (pkt_len_1-frame_tx_idx);
    capture_len -= (pkt_len_1-frame_tx_idx);
    printf("KEY ACK TX pkt size content=%u, diff=%d pkt_len%u cap_len=%d, key_len=%d\n",(u_int16_t)(*content),(frame_to_transmit-start_frame_to_transmit),  pkt_len,capture_len,message_len);
      transmit_on_wifi(config.wifi_inject_pcap,start_frame_to_transmit, pkt_len);
    key_flag =0;
    free(start_frame_to_transmit);
    free(content);
    printf("SESSION KEY ACK TRANSMITTED!! \n");
    exit(-1);
  }else {
    printf("key ack did not work\n");
  }
  return 0 ;
}

int packet_parse(const unsigned char *packet,
		 struct timeval ts,
		 unsigned int capture_len)
{
  u_int16_t radiotap_len=0;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)packet;
  radiotap_len = pletohs(&hdr->it_len);
  if (capture_len <1400) { /*messages are contained in large frames only*/
    return -1;
  }
  //  printf("message injection caplen->%d rad=%d\n",capture_len, radiotap_len);
  if ((key_flag==0 && mode=='c') || (mode=='s' && key_ack_over==1)/*config.session_key_exchanged*/) { //after the keys are exchanged
    if (radiotap_len ==13) {
       printf("message injection caplen->%d rad=%d\n",capture_len, radiotap_len);
      modulo++;
#ifdef FREQ ==1
      if (modulo%1 ==0) //change to 10 later 
	message_injection(packet, radiotap_len, capture_len); 
#elif  FREQ ==2
      if (modulo%3==0 || modulo%5==0 || modulo%7==0){
	//
      } else{
	message_injection(packet, radiotap_len, capture_len); 
      }
#elif FREQ==3
      if (modulo%10000 ==1)
	message_injection(packet, radiotap_len, capture_len); 
#endif
    }
    else { 
      /*need frames that are sent out through device */
      printf("# no 14 %d %d\n",capture_len,radiotap_len);//reception caplen->%d\n",capture_len);
      message_reception(packet, radiotap_len, capture_len); //to be enabled at receiver side
    }
  }else { //code block for key exchange
    if (mode =='s') {
      if (g_key_sent==0) {
	if (radiotap_len ==13) {
	  printf("S:key injection caplen->%d\n",capture_len);
	  key_injection(packet, radiotap_len, capture_len);
	}	
      } else if(g_key_sent==1) { //g_key_sent ==1
	if (radiotap_len >14) { //rcv
	//printf("S:key ack finished caplen->%d %d\n",capture_len, radiotap_len);
        key_ack_finish(packet, radiotap_len, capture_len);
	}	
      } 
    } else if (mode =='c') {
	//  printf("C: client caplen->%d %d\n",capture_len, radiotap_len);
      if (radiotap_len ==13) {
	if (g_key_received ==1 && key_flag==1) {	  
	 //printf("C:key ack received and now transmit caplen->%d %d\n",capture_len, radiotap_len);
	  key_ack_transmit(packet, radiotap_len, capture_len);
	}
      } else { //rad_len==14+
	if(g_key_received ==0) {	  
	 //printf("C:key reception caplen->%d %d\n",capture_len, radiotap_len);
	  key_reception(packet, radiotap_len, capture_len); //to be enabled at receiver side
	}
      }
    }
  }
  return 0;
}

static int ct=0;
int check_tun_frame_content(u_char* orig_covert_frame, 
			    int tun_frame_cap_len)
{
  struct ip *ip;
  struct udp_hdr *udp;
  
  ip = (struct ip *)orig_covert_frame;
  if (tun_frame_cap_len < ip->ip_hl*4 ) { /* didn't capture the full IP header including options */
    printf("IP header with options\n");
    return -1;
  }
  int src_addr =0;
  if (mode =='s')
    src_addr = inet_addr("10.0.0.12");
  else if (mode =='c')
    src_addr = inet_addr("10.0.0.2");

  if (ip->ip_p == IPPROTO_UDP) {
    // printf("UDP packet on TUN interface\n");
    /* Skip over the IP header to get to the UDP header. */
    orig_covert_frame += ip->ip_hl*4;
    udp = (struct udp_hdr*)orig_covert_frame;
    /*/ printf("UDP src_port=%d dst_port=%d length=%d\n",
      ntohs(udp->uh_sport),
      ntohs(udp->uh_dport),
      ntohs(udp->uh_ulen)); */
  }
  else if (ip->ip_p == IPPROTO_TCP) {
      printf("TCP packet %d\n",ip->ip_p);
  }
  else {
    printf("none of the protocol; ICMP mostly ?\n");
  }
  int temp = ip->ip_src.s_addr;
  printf("src=%x \n",ip->ip_src.s_addr);
  printf("dst=%x \n",ip->ip_dst.s_addr);
  printf("src_addr=%x  %x\n",src_addr,temp);
  if (temp==src_addr) {
      printf("bad\n");
      return -1;
  }
  else {
    printf("good %d\n",ct++);
    return 0;
  }
}

int read_rsa_client_priv_key()
{

  FILE*rsa_privkey_file;
  config.rcv_priv_key = NULL;
  rsa_privkey_file = fopen("./keys/privkey.pem", "rb");

  if (!rsa_privkey_file) {
    fprintf(stderr, "Error loading PEM RSA Private Key File.\n");
    return -1;
  }

  if (!PEM_read_RSAPrivateKey(rsa_privkey_file, &config.rcv_priv_key, NULL, NULL)) {
    fprintf(stderr, "Error loading RSA Private Key File.\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (config.rcv_priv_key==NULL) {
    fprintf(stderr,"Could not initialize private key \n");
    return -1;
  }

  return 0;
}

int read_rsa_server_pub_key()
{
  FILE* rsa_pubkey_file;
  config.snd_pub_key  = NULL ;
  rsa_pubkey_file = fopen("./keys/publickey.pub", "rb");

  if (!rsa_pubkey_file) {
    fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
    return -1;
  }

  if (!PEM_read_RSA_PUBKEY(rsa_pubkey_file, &config.snd_pub_key, NULL, NULL))
    {
      fprintf(stderr, "Error loading RSA Public Key File.\n");
      ERR_print_errors_fp(stderr);
      return -1;
    }
  if (config.snd_pub_key==NULL) {
    fprintf(stderr,"Could not initialize public key \n");
    return -1;
  }
  return 0;
}


int main(int argc, char** argv)
{
  u_char buf[PACKET_SIZE];
  char ifname[IF_NAMESIZE];
  int tun_frame_cap_len;

  const u_char * radiotap_packet;
  struct pcap_pkthdr header;

  char * mon_read_ifname="phy0";
  char * mon_inject_ifname="phy2";

  fd_set rd_set;
  
  memcpy(config.salt, (u_int32_t[]) {12345, 54321}, sizeof config.salt);
  config.tun_f_list =NULL;

  int key_msg_len;
  u_char key_msg[]= "20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
  key_msg_len=strlen((char*)key_msg);

  extern char *optarg;
  extern int optind;
  int c, check=0, err=0, ret =0;
  int tflag=0, readmon_flag=0,injectmon_flag=0,mode_flag=0;
  char *tun_ifname = "tun12";
  static char usage[] = "usage: %s [-d] -r read_interface -i inject_inteface -m mode [-s tun_ifname] \n";

  while ((c = getopt(argc, argv, "dtr:i:m:")) != -1)
    switch (c) {
    case 'd':
      debug = 1;
      break;
    case 't':
      tflag = 1;
      tun_ifname = *optarg;
      break;
    case 'r':
      readmon_flag = 1;
      mon_read_ifname = optarg;
      break;
    case 'i':
      injectmon_flag = 1;
      mon_inject_ifname = optarg;
      break;
    case 'm':
      mode_flag = 1;
      mode = *optarg;
      printf(" %c\n",mode);
      if (mode =='c' || mode =='s') {
	printf("Working mode %c\n",mode);
      }else {
	printf("Use (c)lient or (s)erver mode\n");
	exit(-1);
      }
      break;
    case '?':
      err = 1;
      break;
    }
  
  if (readmon_flag == 0) {/* -r is mandatory */
    fprintf(stderr, "%s: missing -r option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if(injectmon_flag==0) {
    fprintf(stderr, "%s: missing -i option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if(mode_flag==0) {
    fprintf(stderr, "%s: missing -m option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if ((optind+1) < argc) {
    /* need at least one argument (change +1 to +2 for two, etc. as needeed) */
    printf("optind = %d, argc=%d\n", optind, argc);
    fprintf(stderr, "%s: missing name\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if (err) {
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  }

   
  config.wifi_inject_pcap= pcap_radiotap_handler(mon_inject_ifname);

  if (pcap_setnonblock(config.wifi_inject_pcap, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(-1);
  }
   if (pcap_set_snaplen(config.wifi_inject_pcap, 65535) ==-1) {
    fprintf(stderr, "can't set inject snaplen %s\n",errbuf);	
  } 

  config.wifi_read_pcap= pcap_radiotap_handler(mon_read_ifname);

  if (config.wifi_read_pcap ==NULL) {
    fprintf(stderr,"pcap file descriptor not avaiable:%s\n",errbuf);
    exit(-1);
  }
   if (pcap_set_snaplen(config.wifi_read_pcap, 65535) ==-1) {
    fprintf(stderr, "can't set read snaplen %s\n",errbuf);	
  } 


  if (pcap_setnonblock(config.wifi_read_pcap, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(-1);
  }
  
  config.pcap_read_fd = pcap_get_selectable_fd(config.wifi_read_pcap);

  strcpy(ifname,tun_ifname);
  if ((config.tun_fd= tun_allocation(ifname)) < 0) {
    fprintf(stderr, "tunnel interface allocation failed\n");
    exit(-1);
  }
  
  //RSA assymetric key cipher
  if ( mode =='s') {
    printf("Denali in server mode\n");
    ret = read_rsa_server_pub_key();
    if(ret ==-1) {
      printf("Could not find sender's public key");
      exit(-1);
    }
    config.shared_key_len= key_msg_len;
    memset(config.shared_key,'\0',key_msg_len);
    memcpy(config.shared_key,key_msg,key_msg_len);

    if((config.encr_shared_key_len = rsa_encrypt())== -1) {
      fprintf(stderr, "RSA Encryption failed\n");
      return -1;
    }
    if (debug) {
      char* b64String = base64Encode(config.encr_shared_key, config.encr_shared_key_len);
      printf("Encrypted message: %s\n", b64String);
    }

    if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
      printf("Couldn't initialize AES cipher\n");
      return -1;
    }
  } else if (mode =='c') {
    printf(" Denali in client mode \n");
    ret = read_rsa_client_priv_key();
    if (ret ==-1) {
      printf("Could not find client's private key");
      exit(-1);
    }
    ret = read_rsa_server_pub_key();
    if(ret ==-1) {
      printf("Could not find sender's public key");
      exit(-1);
    }

  }
  ret = read_rsa_client_priv_key();
  if (ret ==-1) {
      printf("Could not find client's private key");
      exit(-1);
    }

   config.shared_key_len= key_msg_len;
   memset(config.shared_key,'\0',key_msg_len);
   memcpy(config.shared_key,key_msg,key_msg_len);

  //for the client testing only
///*
    if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
      printf("Couldn't initialize AES cipher\n");
      return -1;
    }
//*/


  printf("allocted tunnel interface %s\n", tun_ifname);
  
  int maxfd = (config.tun_fd > config.pcap_read_fd)?config.tun_fd:config.pcap_read_fd;
  while(1)
    {
      int ret;
      
      FD_ZERO(&rd_set);
      FD_SET(config.tun_fd, &rd_set); 
      FD_SET(config.pcap_read_fd, &rd_set);
      ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    
      if (ret < 0 && errno == EINTR)
	continue;
      if (ret < 0) {
	perror("select()");
	exit(1);
      }
      if(FD_ISSET(config.tun_fd, &rd_set)) {
	memset(buf,0,sizeof(buf));
	if ((tun_frame_cap_len = read(config.tun_fd, buf, sizeof(buf))) < 0) {
	  perror("read() on tun file descriptor");
	  close(config.tun_fd);
	  exit(1);
	}
	check=check_tun_frame_content(buf, tun_frame_cap_len);
	if (check==0 /*&& config.session_key_exchanged*/) {
	  end_add_element(&config.tun_f_list, buf ,tun_frame_cap_len);
	  list_size++;
	  g_pkt_send++;
	} else {
    	printf("exchange status: %d\n",config.session_key_exchanged);
    }
	printf("%02x %02x %02x %02x \n",*buf, *(buf+1), *(buf+2),*(buf+3));
	printf("read %d bytes from tunnel interface %s.\n-----\n", tun_frame_cap_len, tun_ifname);
      }
      if(FD_ISSET(config.pcap_read_fd, &rd_set)) {
	radiotap_packet = pcap_next(config.wifi_read_pcap, &header);
	if (header.caplen>1700) {
	  //if (header.caplen!=header.len) {
	  printf(" %d %d ",header.caplen,header.len);
	  return -1;
	}
	
	packet_parse(radiotap_packet, header.ts, header.caplen);
      }
    }
  return 0;
}
