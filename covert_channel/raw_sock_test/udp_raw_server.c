/* 
Author: Abhinav Narain

Purpose : Runs a RAW socket UDP server on a tun interface


Source has partial snippets from different authors on Internet,
and understanding pcap/tcpdump source code.
I duly acknowledge them and I have made reasonable changes reading
Steven's to get a server that works (There are RAW socket senders, but 
not receivers.
*/
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h> 
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>

#define PACKET_LEN 1500

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

// UDP header's structure
struct udpheader {
  unsigned short int udph_srcport;
  unsigned short int udph_destport;
  unsigned short int udph_len;
  unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)
unsigned short csum(unsigned short *buf, int nwords)
{       //
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}
/*Not needed to put the interface in promiscuous mode.
Might be useful to put it when sniffing on the interface.*/
static int promisc(int sock_fd, int ifindex)
{
  struct packet_mreq  mr;
  memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = ifindex;
  mr.mr_type    = PACKET_MR_PROMISC;
  if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		 &mr, sizeof(mr)) == -1) {
    printf("setsockopt: PACKET_ADD_MEMBERSHIP");
    close(sock_fd);
    return -1;
  }
  return 0;
}
/*Bind the server to the interface on a fixed IP address*/
static int iface_bind(int fd, int ifindex, u_char * ip_addr)
{
  /*
  struct sockaddr_ll  sll;
  
  memset(&sll, 0, sizeof(sll));
  sll.sll_family      = AF_PACKET;
  sll.sll_ifindex     = ifindex;
  sll.sll_protocol    = htons(ETH_P_ALL);
  */
  int err;
  socklen_t errlen = sizeof(err);  
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(2223);
  sin.sin_addr.s_addr = inet_addr(ip_addr);

  if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
    printf("Cannot bind to the interface ");
    return -1;
  }

  return 0;  
}
/*Set the IP address of the interface*/
int set_addr(int fd, u_char * server_ip_addr, const char *device)
{
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_addr.sa_family = AF_INET;
  //strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  inet_pton(AF_INET, server_ip_addr, &ifr.ifr_addr.sa_data);
  if (ioctl(fd,  SIOCSIFADDR, &ifr) ==-1)
    {
      printf("Can't set the IP address of the interface");
      return -1; 
    }
  return 0;
}
/*Get the id of the interface corresponding to the device*/
static int iface_get_id(int fd, const char *device)
{
  struct ifreq  ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

  if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
    printf("Can't get iface index");
    return -1;
  }
  return ifr.ifr_ifindex;
}
/*Get the type of ARP on the interface; mostly has to 
be the usual ARP as it is IP type; not PPP etc types*/
static int iface_get_arptype(int fd, const char *device)
{
  struct ifreq    ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
    printf("SIOCGIFHWADDR: error\n");
    return -1;
  }

  return ifr.ifr_hwaddr.sa_family;
}
int iface_get_socket()
{
  int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if(sd < 0)
    {
      return -1;
    }
  else{
    printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
  }
  return sd;
}
int ip_create_header(){
  /*
  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  ip->iph_ihl = 5;
  ip->iph_ver = 4;
  ip->iph_tos = 16; // Low delay
  ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
  ip->iph_ident = htons(54321);
  ip->iph_ttl = 64; // hops
  ip->iph_protocol = 17; // UDP
  // Source IP address, can use spoofed address here!!!
  ip->iph_sourceip = inet_addr(argv[1]);
  // The destination IP address
  ip->iph_destip = inet_addr(argv[3]);
 */
  return 0; 
}
int main(int argc, char *argv[])
{
  int sd;
  char buffer[PACKET_LEN];
  int one = 1;
  const int *val = &one;
  memset(buffer, 0, PACKET_LEN);

  struct sockaddr_ll  from;
  int packet_len, arptype, if_index ;
  socklen_t fromlen;
  const char *device ="tun2";
  // Create a raw socket with UDP protocol
  sd = iface_get_socket();
  if (sd ==-1)
    {
      printf("Can't get a raw socket ");
      exit(-1);
    }
  arptype =iface_get_arptype(sd, device);
  if_index= iface_get_id(sd,device);
  u_char * server_ip_addr="10.0.0.12";

  //promisc(sd,if_index);
  //set_addr(sd,server_ip_addr,device);
  if (iface_bind(sd,if_index,server_ip_addr)==-1)
    {
      printf("Can't bind to socket\n");
      close(sd);
      exit(-1);
    }

  // Fabricate the UDP header. Source port number, redundant
  /*
  udp->udph_srcport = htons(atoi(argv[2]));
  // Destination port number
  udp->udph_destport = htons(atoi(argv[4]));
  udp->udph_len = htons(sizeof(struct udpheader));
  u_char *  t= "The mordor scene tends to be really good these days but Sauramon is having his own evil plans that want to engulf the lower middle earth and then have people die with his evil army taking over and making the most out of it";
  int a =  sizeof( "The mordor scene tends to be really good these days but Sauramon is having his own evil plans that want to engulf the lower middle earth and then have people die with his evil army taking over and making the most out of it");
  memcpy(buffer+sizeof(struct udpheader),t, a);
  */
  /*
  // Calculate the checksum for integrity
  ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
  // Inform the kernel do not fill up the packet structure. we will build our own...
  if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
      perror("setsockopt() error");
      exit(-1);
    }
  else
    printf("setsockopt() is OK.\n");
*/ 
  // Send loop, send for every 2 second for 100 count
  printf("Trying...\n");
  printf("Using raw socket and UDP protocol\n");
  u_char* text;
  static int l=0;
  while(1)
  {
    printf("loop=%d\n",l++);
    packet_len=recvfrom(sd,buffer,1000, MSG_TRUNC,(struct sockaddr *)&from, &fromlen);
    if (packet_len ==-1)
    {
      printf("Error in recvfrom\n");
      break;
    }
    struct ip *ip = (struct ip*)buffer;
    printf("hlen=%d tot=%d pkt_len=%d ttl=%d\n", ip->ip_hl, ntohs(ip->ip_len),packet_len,ip->ip_ttl);
    if (ip->ip_p != IPPROTO_UDP)
      {
        printf( "non-UDP packet\n");
      }
    else
    {
        printf("UDP packet\n");
    }
    int ip_offset = ntohs(ip->ip_off);
    int offset=0;
    
    printf("flag= %x\n",(ip->ip_off & 0xe000));
   // IP_DF 0x4000            /* dont fragment flag */
   // IP_MF 0x2000            /* more fragments flag */
    if (ip_offset & IP_OFFMASK )
    { //implies a udp header is present
    int offset = (ip_off & IP_OFFMASK) << 3;
    int more= (ip_off & IP_MF) ? 1 : 0;
    struct udpheader *tu= (struct udpheader *)(buffer+sizeof(struct ip));
    printf("after src_port =%u\n", ntohs(tu-> udph_srcport));
    printf("after dest_port = %u\n",ntohs(tu->udph_destport));
    text=(u_char*)(buffer+sizeof(struct ip)+sizeof(struct udpheader));
    printf("text1 is: %s\n",text);
    }
    else
    {
    text =(u_char*)(buffer+sizeof(struct ip));
    printf("text2 is: %s\n",text);
    }
  }
  close(sd);
  return 0;
}
 
