#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include <string.h>
#include <math.h>
/*
  Part of code is taken from StackOverflow discussions and combined with the following link code
  https://shanetully.com/2012/06/openssl-rsa-aes-and-c
 */
/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}


/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
static u_char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static u_char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}
/*
returns the Encrypted cipher frame using the key.
Also gives the SHA 256 of the encrypted frame (cipher frame)
*/
int encrypt_digest(EVP_CIPHER_CTX *en,
		   u_char* frame,
		   u_char** encr_frame,
		   int* encr_frame_len)
{
  
  *encr_frame = aes_encrypt(en,frame, encr_frame_len);
  if (*encr_frame ==NULL)
    return -1;    
  return 0;
}

/*
returns the Decrypted cipher frame(already uncompressed), using the key.
Also gives the SHA 256 of the cipher text.
*/
int decrypt_digest(EVP_CIPHER_CTX *de,
		   u_char* pUncomp_cipher_frame, 
		   u_char** decr_frame,
		   int* decr_frame_len)
{
  *decr_frame = aes_decrypt(de, pUncomp_cipher_frame, decr_frame_len);
  if (*decr_frame ==NULL)
    return -1;
  return 0;
}

/*
returns the Compressed the cipher frame and the compressed length.
*/
int compress_cipher_frame(u_char **pCmp_cipher_frame,
			  ulong *compressed_frame_len,
			  u_char * cipher_frame,
			  int cipher_frame_len)
{
  int cmp_status;
  *pCmp_cipher_frame = (u_int8_t *)malloc((size_t)*compressed_frame_len);
  if (!pCmp_cipher_frame)
    {
      printf("Out of memory!\n");
      return EXIT_FAILURE;
    }  
  cmp_status = compress(*pCmp_cipher_frame, compressed_frame_len, (const u_char *)cipher_frame, cipher_frame_len);
  if (cmp_status != Z_OK)
    {
      //printf("compress() failed!\n");
      free(pCmp_cipher_frame);
      return EXIT_FAILURE;
    }

  return 0;
}


/*
returns the uncompressed frame and its length.
*/

int  uncompress_cipher_frame(u_char** pUncomp_cipher_frame,
			     u_char* pCmp_cipher_frame,
			     ulong *uncompressed_frame_len,
			     ulong compressed_frame_len)
{
  int cmp_status;
  u_char temp[2000];
  cmp_status = uncompress(temp, uncompressed_frame_len, pCmp_cipher_frame, compressed_frame_len);
  if (cmp_status != Z_OK)
    {
    //  printf("uncompress failed!\n");
      return EXIT_FAILURE;
    }
  *pUncomp_cipher_frame = (u_int8_t *)malloc((size_t)*uncompressed_frame_len);
  if (!pUncomp_cipher_frame)
    {
      printf("Out of memory!\n");
      return EXIT_FAILURE;
    } 
  memset(*pUncomp_cipher_frame ,0,*uncompressed_frame_len);
  memcpy(*pUncomp_cipher_frame ,temp,*uncompressed_frame_len);
  
  return 0;
}


int rsa_encrypt()
{
  int result = RSA_public_encrypt(config.shared_key_len , config.shared_key ,config.encr_shared_key,config.snd_pub_key, RSA_PKCS1_PADDING);
  return result;

}

int rsa_decrypt()
{
  int  result = RSA_private_decrypt(config.encr_shared_key_len,config.encr_shared_key,config.decr_shared_key,config.rcv_priv_key, RSA_PKCS1_PADDING);
  return result;

}

//Not required for crypto API but used for debug
//$ ssh-keygen -y -f mykey.pem > mykey.pub
//openssl genrsa -out mykey.pem 2048
//openssl rsa -in mykey.pem -pubout > mykey.pub

#define KEY_PRI 0 
#define KEY_PUB 1 

int printKey(FILE *fd, int code, EVP_PKEY * key) 
{
  switch(code) 
    {
    case KEY_PRI:
      printf("server pri\n");
      if(!PEM_write_PrivateKey(fd, key, NULL, NULL, 0, 0, NULL)) {
	return -1;
      }
    break;
    
    case KEY_PUB:
    printf("server pub\n");
    if(!PEM_write_PUBKEY(fd, key)) {
      return -1;
    }
    break;
    
    default:
      return -1;
    }
  return 0;
}

char* base64Encode(const u_char *message,
		   const size_t length) 
{
  BIO *bio;
  BIO *b64;
  FILE* stream;

  int encodedSize = 4*ceil((double)length/3);
  char *buffer = (char*)malloc(encodedSize+1);
  if(buffer == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }
     
  stream = fmemopen(buffer, encodedSize+1, "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, message, length);
  (void)BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  return buffer;
}

static int calcDecodeLength(const char *b64input, const size_t length) {
  int padding = 0;
    
  // Check for trailing '=''s as padding
  if(b64input[length-1] == '=' && b64input[length-2] == '=')
    padding = 2;
  else if (b64input[length-1] == '=')
    padding = 1;
     
  return (int)length*0.75 - padding;
}
 
int base64Decode(const char *b64message, const size_t length, u_char **buffer) {
  BIO *bio;
  BIO *b64;
  int decodedLength = calcDecodeLength(b64message, length);

  *buffer = (u_char*)malloc(decodedLength+1);
  if(*buffer == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }
  FILE* stream = fmemopen((char*)b64message, length, "r");
     
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  decodedLength = BIO_read(bio, *buffer, length);
  (*buffer)[decodedLength] = '\0';
     
  BIO_free_all(bio);
  fclose(stream);
     
  return decodedLength;
}


#if 0
int main(int argc, char **argv)
{
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations 
  */
  EVP_CIPHER_CTX en, de;

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 
  */
  u_int32_t salt[] = {12345, 54321};
  u_char key_data []= "This is the key";
  int key_data_len;
  ulong  compressed_frame_len, uncompressed_frame_len;
  u_int8_t *pCmp_cipher_frame, *pUncomp_cipher_frame;
  u_char *decrypted_frame;
  int decrypted_frame_len, cipher_frame_len, orig_frame_len,sha_len;
  u_char * sha_orig_frame,*sha_decr_frame;
  u_char* cipher_frame;
  key_data_len = strlen(key_data);
  u_char frame [] = "I want to see the relative diffence in the length of the ciphertext. It seems the gap between the two keeps decreasing ever so slowly and might turn out that the size is dereasing with the increaseing text size. It seems to have stopped to a point when they are four bytes apart all the time no matter how long the plaintext is";
  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }
  /* encrypt and decrypt each frame string and compare with the original */

  /* The enc/dec functions deal with binary data and not C strings. strlen() will 
     return length of the string without counting the '\0' string marker. We always
     pass in the marker byte to the encrypt/decrypt functions so that after decryption 
       we end up with a legal C string 
  */
  cipher_frame_len = orig_frame_len = sizeof(frame);
  enrypt_digest(&en,frame,&sha_orig_frame, &cipher_frame,&cipher_frame_len,key_data,key_data_len);
  compressed_frame_len = compressBound(cipher_frame_len);
  compress_cipher_frame(&pCmp_cipher_frame, &compressed_frame_len, cipher_frame, cipher_frame_len);
  uncompress_cipher_frame(&pUncomp_cipher_frame, pCmp_cipher_frame, &uncompressed_frame_len, compressed_frame_len);
  decrypted_frame_len=cipher_frame_len;
  decrypt_digest(&de,pUncomp_cipher_frame, &sha_decr_frame, &decrypted_frame,&decrypted_frame_len,key_data,key_data_len);
  if ((uncompressed_frame_len != cipher_frame_len) || (memcmp(pUncomp_cipher_frame, cipher_frame, (size_t)cipher_frame_len)))
    {
      printf("Decompression failed!\n");
      free(pCmp_cipher_frame);
      free(pUncomp_cipher_frame);
      return EXIT_FAILURE;
    }
  printf("the decrypted_frame len=%d\n", decrypted_frame_len);
  if (strncmp((const char*)decrypted_frame,frame, (const char*)cipher_frame_len)) 
    printf("FAIL: enc/dec failed for \n");
  else 
    printf("OK: enc/dec ok for \"%s\"\n", decrypted_frame);

  free(cipher_frame);
  free(decrypted_frame);
 
  free(pCmp_cipher_frame);
  free(pUncomp_cipher_frame);

  printf("end of compression compression part\n"); 
  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);
  return 0;
}
#endif
