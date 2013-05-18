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

#include <openssl/hmac.h>

@implementation NSData (RadCrypto)

- (NSData *) md5Data 
{
	return nil; // TODO
}

- (NSData *) sha1Data
{
	return nil;	
}

- (NSData *) sha224Data
{
	return nil;	
}

- (NSData *) sha256Data
{
	return nil;	
}

- (NSData *) sha384Data
{
	return nil;	
}

- (NSData *) sha512Data
{
	return nil;	
}

- (NSData *) hmacMd5DataWithKey:(NSData *) key
{
	return nil;	
}

- (NSData *) hmacSha1DataWithKey:(NSData *) key {
	// Using sha1 hash engine here.
	// You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
   	unsigned char *digest = HMAC(EVP_sha1(), [key bytes], [key length], [self bytes], [self length], NULL, NULL);    
	return [NSData dataWithBytes:digest length:20];
}

- (NSData *) hmacSha224DataWithKey:(NSData *) key
{
	return nil;	
}

- (NSData *) hmacSha256DataWithKey:(NSData *) key
{
	return nil;	
}

- (NSData *) hmacSha384DataWithKey:(NSData *) key
{
	return nil;	
}

- (NSData *) hmacSha512DataWithKey:(NSData *) key
{
	return nil;	
}

- (NSMutableData*) aesEncryptWithKey:(NSString *) key
{
	return nil;	
}

- (NSMutableData*) aesDecryptWithKey:(NSString *) key
{
	return nil;	
}

@end
#endif
