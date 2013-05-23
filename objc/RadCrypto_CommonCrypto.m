/*!
 @file RadCrypto_CommonCrypto.m
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
#ifdef RadCrypto_CommonCrypto

#import "RadCrypto.h"

#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

@implementation NSData (RadCommonCrypto)

- (NSData *) md5Data
{
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_MD5_DIGEST_LENGTH];
}

- (NSData *) sha1Data
{
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA1_DIGEST_LENGTH];
}

- (NSData *) sha224Data
{
    unsigned char result[CC_SHA224_DIGEST_LENGTH];
    CC_SHA224([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA224_DIGEST_LENGTH];
}

- (NSData *) sha256Data
{
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA256_DIGEST_LENGTH];
}

- (NSData *) sha384Data
{
    unsigned char result[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA384_DIGEST_LENGTH];
}

- (NSData *) sha512Data
{
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512([self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA512_DIGEST_LENGTH];
}

- (NSData *) hmacMd5DataWithKey:(NSData *) key
{
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgMD5, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_MD5_DIGEST_LENGTH];
}

- (NSData *) hmacSha1DataWithKey:(NSData *) key
{
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA1_DIGEST_LENGTH];
}

- (NSData *) hmacSha224DataWithKey:(NSData *) key
{
    unsigned char result[CC_SHA224_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA224, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA224_DIGEST_LENGTH];
}

- (NSData *) hmacSha256DataWithKey:(NSData *) key
{
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA256_DIGEST_LENGTH];
}

- (NSData *) hmacSha384DataWithKey:(NSData *) key
{
    unsigned char result[CC_SHA384_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA384, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA384_DIGEST_LENGTH];
}

- (NSData *) hmacSha512DataWithKey:(NSData *) key
{
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA512, [key bytes], [key length], [self bytes], [self length], result);
    return [NSData dataWithBytes:result length:CC_SHA512_DIGEST_LENGTH];
}

const NSUInteger kPBKDFRounds = 10000;  // ~80ms on an iPhone 4

// Replace this with a 10,000 hash calls if you don't have CCKeyDerivationPBKDF
+ (NSData *) AESKeyForPassword:(NSString *)password 
                          salt:(NSString *)salt {
  NSMutableData *derivedKey = [NSMutableData dataWithLength:kCCKeySizeAES256];
  int result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                    password.UTF8String,  // password
                                    password.length,      // passwordLength
                                    salt.UTF8String,           // salt
                                    salt.length,          // saltLen
                                    kCCPRFHmacAlgSHA1,    // PRF
                                    kPBKDFRounds,         // rounds
                                    derivedKey.mutableBytes, // derivedKey
                                    derivedKey.length); // derivedKeyLen
  // Do not log password here
  NSAssert(result == kCCSuccess, @"Unable to create AES key for password: %d", result);
  return derivedKey;
}

- (NSData *) aesEncryptedDataWithPassword:(NSString *) password salt:(NSString *) salt
{
    size_t numBytesEncrypted = 0;
    NSUInteger dataLength = [self length];    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);        
    NSData *key = [isa AESKeyForPassword:password salt:salt];
    CCCryptorStatus result = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                     [key bytes], [key length],
                                     NULL,
                                     [self bytes], [self length],
                                     buffer, bufferSize,
                                     &numBytesEncrypted);  
    if (result == kCCSuccess) {
	return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    return nil;
}

- (NSData *) aesDecryptedDataWithPassword:(NSString *) password salt:(NSString *) salt
{
    size_t numBytesDecrypted = 0;
    NSUInteger dataLength = [self length];    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    NSData *key = [isa AESKeyForPassword:password salt:salt];
    CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                     [key bytes], [key length],
                                     NULL,
                                     [self bytes], [self length],
                                     buffer, bufferSize,
                                     &numBytesDecrypted);    
    if (result == kCCSuccess) {
    	return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    return nil;
}

@end

#if TARGET_OS_IPHONE

@interface RadPublicRSAKey : NSObject
{
    SecKeyRef publicKey;
    BOOL valid;
}
@property (nonatomic, assign, readonly) BOOL valid;

- (id) initWithCertificateData:(NSData *) certificateData;
- (NSData *) encryptData:(NSData *) data;
@end

@interface RadPrivateRSAKey : NSObject 
{
    NSString *name;
    NSData *publicTag;
    NSData *privateTag;
    SecKeyRef publicKeyRef;
    SecKeyRef privateKeyRef;
    BOOL valid;
}
@property (nonatomic, assign, readonly) BOOL valid;

- (id) initWithName:(id) n;
- (void)deleteAsymmetricKeys;
- (BOOL) generateKeyPair:(NSUInteger)keySize;
- (NSData *)getPublicKeyBits;
- (SecKeyRef)getPrivateKeyRef;
- (NSData *)decryptData:(NSData *) encryptedData;
@end


@interface RadPrivateRSAKey (Private)
- (BOOL) generateKeyPair:(NSUInteger)keySize;
@end

@implementation RadPrivateRSAKey 
@synthesize valid;

- (id) initWithName:(id) n {
    if (self = [super init]) {
        self->name = n;
        self->publicTag = [[name stringByAppendingString:@"-public"] dataUsingEncoding:NSUTF8StringEncoding];
        self->privateTag = [[name stringByAppendingString:@"-private"] dataUsingEncoding:NSUTF8StringEncoding];        

        if ([self getPrivateKeyRef]) {
            NSLog(@"key pair already exists");
            valid = YES;
        } else {
            NSLog(@"generating key pair");
            valid = [self generateKeyPair:1024];
        }        
    }
    return self;
}

- (void) dealloc {
    CFRelease(publicKeyRef);
    CFRelease(privateKeyRef);
}

- (void)deleteAsymmetricKeys {    
	// Delete the public key.
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
	if (publicKeyRef) CFRelease(publicKeyRef);
    publicKeyRef = NULL;
    
	// Delete the private key.
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
	[queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];	
    SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);			
	if (privateKeyRef) CFRelease(privateKeyRef);
    privateKeyRef = NULL;
}

- (BOOL) generateKeyPair:(NSUInteger)keySize {
    
    CFStringRef kSecPrivateKeyAttrs = CFSTR("private");
    CFStringRef kSecPublicKeyAttrs = CFSTR("private");
	
	// First delete current keys.
	[self deleteAsymmetricKeys];
    
	// Set the private key dictionary.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
	[privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
	[privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
	// See SecKey.h to set other flag values.
	
	// Set the public key dictionary.
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
	[publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
	[publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	// See SecKey.h to set other flag values.
	
    // Set top level dictionary for the keypair.
	NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
	[keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];    
	[keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
	[keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
	
	// SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
	OSStatus sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    
    
    return (sanityCheck == noErr);
}

- (NSData *)getPublicKeyBits {
    
	// Set the public key query dictionary.
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
	// Get the key bits.
    NSData * publicKeyBits = nil;
    assert(0); // broken in ARC conversion
//	OSStatus sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, ((__bridge CFTypeRef) *)&publicKeyBits);
//	if (sanityCheck != noErr)
//	{
		publicKeyBits = nil;
//	}
	return publicKeyBits;
}

- (SecKeyRef)getPrivateKeyRef {
    
    assert(0); // broken in ARC conversion
#ifdef BROKEN
    // Set the private key query dictionary.
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
#endif
    // Get the key.
    SecKeyRef privateKeyReference = NULL;
//    OSStatus resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, ((__bridge CFTypeRef) *)&privateKeyReference);    
//    if(resultCode != noErr)
//    {
        privateKeyReference = NULL;
//    }    
//    [queryPrivateKey release];    
    return privateKeyReference;
}


- (NSData *)decryptData:(NSData *) encryptedData 
{
    size_t cipherBufferSize = [encryptedData length];
    char *cipherBuffer = (char *) malloc(cipherBufferSize * sizeof(char));
    memcpy(cipherBuffer, [encryptedData bytes], cipherBufferSize);
    
    const int BUFFER_SIZE = 128;
    size_t plainBufferSize = BUFFER_SIZE;
    uint8_t *plainBuffer = (uint8_t *) malloc(BUFFER_SIZE * sizeof(uint8_t));    
    OSStatus status = SecKeyDecrypt([self getPrivateKeyRef],
                                    kSecPaddingPKCS1,
                                    (const uint8_t *) cipherBuffer,
                                    cipherBufferSize,
                                    &plainBuffer[0],
                                    &plainBufferSize);
    free(cipherBuffer);    
    id result = nil;
    if (status == noErr) {
        // null-terminate for prudence
        if (plainBufferSize < BUFFER_SIZE) {
            plainBuffer[plainBufferSize] = 0;
            plainBufferSize++;
        }
        result = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
        free(plainBuffer);
    }
    return result;
}   

@end

@implementation RadPublicRSAKey 
@synthesize valid;


- (id) initWithCertificateData:(NSData *) certificateData {
    if (self = [super init]) {
        SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef) certificateData);
        if (!certificate) {
            NSLog(@"Failed to parse certificate");
            valid = NO;
            return self;
        }
        
        // This chain of steps is necessary to get the public key from the certificate.
        SecTrustRef trustRef;
        OSStatus status = SecTrustCreateWithCertificates (certificate, nil, &trustRef);
        if (status != 0) {
            NSLog(@"Unable to create trust with certificates");
            valid = NO;
            return self;
        }
        
        // Evaluates trust for the specified certificate and policies.        
        SecTrustResultType trustResult;
        status = SecTrustEvaluate (trustRef, &trustResult);
        if (status != 0) {
            NSLog(@"Certificate failed trust evaluation");
            valid = NO;
            return self;
        }              
        
        self->publicKey = SecTrustCopyPublicKey(trustRef);
        
        if (!publicKey) {
            NSLog(@"Failed to read public key");
            valid = NO;
            return self;
        }
        
        if (status != noErr) {
            NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:NULL];
            NSLog(@"Error: %@", [error description]);
            valid = NO;
            return self;
        }        
        valid = YES;
    }
    return self;
}

- (NSData *) encryptData:(NSData *) data {   
    const size_t CIPHER_BUFFER_SIZE = 128;
    uint8_t cipherBuffer[CIPHER_BUFFER_SIZE];
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    
    // Encrypt using the public key.
    OSStatus status = SecKeyEncrypt(publicKey,
                                    kSecPaddingPKCS1,
                                    [data bytes],
                                    [data length],
                                    &cipherBuffer[0],
                                    &cipherBufferSize);    
    if (status == noErr) {    
        return [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    } else {
        return nil;
    }
}

@end

#endif
#endif
