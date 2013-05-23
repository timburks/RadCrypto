/*!
 @file RadCrypto_OpenSSL.m
 @copyright Copyright (c) 2013 Radtastical, Inc.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
#ifdef RadCrypto_OpenSSL

#import "RadCrypto.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

@implementation NSData (RadCrypto)

- (NSData *) md5Data 
{
	return [NSData dataWithBytes:MD5([self bytes], [self length], NULL) length:MD5_DIGEST_LENGTH];
}

- (NSData *) sha1Data
{
	return [NSData dataWithBytes:SHA1([self bytes], [self length], NULL) length:SHA_DIGEST_LENGTH];
}

- (NSData *) sha224Data
{
	return [NSData dataWithBytes:SHA224([self bytes], [self length], NULL) length:SHA224_DIGEST_LENGTH];
}

- (NSData *) sha256Data
{
	return [NSData dataWithBytes:SHA256([self bytes], [self length], NULL) length:SHA256_DIGEST_LENGTH];
}

- (NSData *) sha384Data
{
	return [NSData dataWithBytes:SHA384([self bytes], [self length], NULL) length:SHA384_DIGEST_LENGTH];
}

- (NSData *) sha512Data
{
	return [NSData dataWithBytes:SHA512([self bytes], [self length], NULL) length:SHA512_DIGEST_LENGTH];
}

- (NSData *) hmacMd5DataWithKey:(NSData *) key
{
	unsigned int length;
   	unsigned char *digest = HMAC(EVP_md5(), [key bytes], [key length], [self bytes], [self length], NULL, &length);    
	return [NSData dataWithBytes:digest length:length];	
}

- (NSData *) hmacSha1DataWithKey:(NSData *) key {
	unsigned int length;	
   	unsigned char *digest = HMAC(EVP_sha1(), [key bytes], [key length], [self bytes], [self length], NULL, &length);    
	return [NSData dataWithBytes:digest length:length];
}

- (NSData *) hmacSha224DataWithKey:(NSData *) key
{
	unsigned int length;
   	unsigned char *digest = HMAC(EVP_sha224(), [key bytes], [key length], [self bytes], [self length], NULL,  &length);    
	return [NSData dataWithBytes:digest length:length];
}

- (NSData *) hmacSha256DataWithKey:(NSData *) key
{
	unsigned int length;
   	unsigned char *digest = HMAC(EVP_sha256(), [key bytes], [key length], [self bytes], [self length], NULL,  &length);    
	return [NSData dataWithBytes:digest length:length];
}

- (NSData *) hmacSha384DataWithKey:(NSData *) key
{
	unsigned int length;
   	unsigned char *digest = HMAC(EVP_sha384(), [key bytes], [key length], [self bytes], [self length], NULL,  &length);    
	return [NSData dataWithBytes:digest length:length];
}

- (NSData *) hmacSha512DataWithKey:(NSData *) key
{
	unsigned int length;
   	unsigned char *digest = HMAC(EVP_sha512(), [key bytes], [key length], [self bytes], [self length], NULL,  &length);    
	return [NSData dataWithBytes:digest length:length];
}

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	int nrounds = 10000;
  	unsigned char key[32], iv[32];
  
  	/*
   	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
         * nrounds is the number of times the we hash the material. More rounds are more secure but
         * slower.
         */
  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
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
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
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
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
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

- (NSData *) aesEncryptedDataWithPassword:(NSString *) password salt:(NSString *) salt
{
  	EVP_CIPHER_CTX en, de;
    	if (aes_init([password UTF8String], [password length], [salt UTF8String], &en, &de)) {
    		printf("Couldn't initialize AES cipher\n");
    		return nil;
  	} 
	int olen = [self length];
	int len = [self length];	
   	unsigned char *ciphertext = aes_encrypt(&en, [self bytes], &len);
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
	return [NSData dataWithBytesNoCopy:ciphertext length:len];
}

- (NSData *) aesDecryptedDataWithPassword:(NSString *) password salt:(NSString *) salt
{
  	EVP_CIPHER_CTX en, de;
    	if (aes_init([password UTF8String], [password length], [salt UTF8String], &en, &de)) {
    		printf("Couldn't initialize AES cipher\n");
    		return nil;
  	}
	int olen = [self length];
	int len = [self length];	
   	unsigned char *plaintext = aes_decrypt(&de, [self bytes], &len);
  	EVP_CIPHER_CTX_cleanup(&en);
  	EVP_CIPHER_CTX_cleanup(&de);
	return [NSData dataWithBytesNoCopy:plaintext length:len];
}

@end



#endif
