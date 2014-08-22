#ifndef _COVERT_CONFIG_H_
#define __COVERT_CONFIG_H_
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <pcap.h>
#define SALT_SIZE 2
#define PACKET_SIZE 65535
#define CRC_BYTES_LEN 4
#define H_MAC_BYTES_LEN 4 /*hmac of the message to be calculated and store. message will be stored in front of HMAC*/
#define MSG_BYTES_LEN 2   /*gives the length of the encrypted message*/
#define TCP_OPTIONS 12    /*TODO: find out the size of the tcp options in the connection from header*/
#define MAX_MTU_SIZE 150
#define MAC_HDR 6
#define SHORT_SIZE 2
#define SHA_SIZE 32

struct node {
  u_char* data;
  int data_len;
  u_char* cipher_data;
  int cipher_data_len;
  u_char * hmac_cipher_data;
  struct node *next;
};
typedef struct node node;

typedef struct global_config {
  int tun_fd;
  int pcap_read_fd;
  pcap_t* wifi_read_pcap;
  pcap_t* wifi_inject_pcap;

  u_char shared_key[1000];
  int shared_key_len;

  u_int32_t salt[SALT_SIZE] ;

  RSA * snd_pub_key;
  RSA * rcv_priv_key;
  
  node * tun_f_list ;

  EVP_CIPHER_CTX en;
  EVP_CIPHER_CTX de;

  EVP_CIPHER_CTX rsa_en;
  EVP_CIPHER_CTX rsa_de;

  u_char encr_shared_key[1000];
  int encr_shared_key_len;
  
  u_char decr_shared_key[1000];
  int decr_shared_key_len;


  int session_key_exchanged;
} config_;
extern config_ config;

#endif /*_COVERT_CONFIG_H_*/
