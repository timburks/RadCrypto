/*!
 @file RadSSL.h
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

// WARNING - EVERYTHING IN THIS FILE IS EXPERIMENTAL JUNK AND SUBJECT TO CHANGE

// since this requires OpenSSL, we omit it from iPhone builds
#if !TARGET_OS_IPHONE

@interface RadSSL : NSObject

- (void) setCAListFileName:(NSString *)CAListFileName;
- (void) setCAListData:(NSData *) cert_data;
- (void) setCAListText:(NSString *) cert_string;

- (void) setCertificateFileName:(NSString *)certificateFileName;
- (void) setCertificateData:(NSData *) cert_data;
- (void) setCertificateText:(NSString *) cert_string;

- (void) setKeyFileName:(NSString *)keyFileName;
- (void) setKeyData:(NSData *) key_data;
- (void) setKeyText:(NSString *) key_string;

- (BOOL) sendPayload:(NSString *) payloadString toDeviceWithToken:(NSString *) deviceTokenString;
- (void) connectToHost:(NSString *) host port:(int) port;
- (void) closeConnection;

@end

@interface NSData (RadSSL)
+ (NSData *) dataWithBIO:(BIO *) bio;
@end

@interface RadRSAKey : NSObject {
@public
    RSA *rsa;
}
- (id) initWithPrivateKeyData:(NSData *) key_data;
- (id) initWithPrivateKeyText:(NSString *) key_string;
- (int) checkKey;
@end

@interface RadEVPPKey : NSObject {
@public
    EVP_PKEY *pkey;
}
- (id) initWithRSAKey:(RadRSAKey *) rsaKey;
@end

@interface RadX509Request : NSObject {
    X509_REQ *req;
}
@end

@interface RadX509Certificate : NSObject {
@public
    X509 *cert;
}
- (id) initWithData:(NSData *) cert_data;
- (id) initWithText:(NSString *) cert_string;
- (id) initWithX509:(X509 *) x509;
- (NSString *) name;
- (NSData *) dataRepresentation;
- (NSString *) textRepresentation;
@end

@interface RadPKCS7Message : NSObject {
@public
    PKCS7 *p7;
}

+ (void) initialize;
+ (RadPKCS7Message *) signedMessageWithCertificate:(RadX509Certificate *) certificate
                                        privateKey:(RadEVPPKey *) key
                                              data:(NSData *) dataToSign
                                  signedAttributes:(NSDictionary *) signedAttributes;
+ (RadPKCS7Message *) degenerateWrapperForCertificate:(RadX509Certificate *) certificate;
+ (RadPKCS7Message *) encryptedMessageWithCertificates:(NSArray *) certificates
                                                  data:(NSData *) dataToEncrypt;
- (id) initWithData:(NSData *) data;
- (id) initWithPKCS7:(PKCS7 *) pkcs7;
- (NSData *) dataRepresentation;
- (NSString *) textRepresentation;
- (NSData *) decryptWithKey:(RadEVPPKey *) key
                certificate:(RadX509Certificate *) certificate;
- (RadX509Certificate *) signerCertificate;
- (NSDictionary *) attributes;
- (NSData *) verifyWithCertificate:(RadX509Certificate *) certificate;
@end

@interface RadCertificateAuthority : NSObject

- (RadX509Certificate *) generateCertificateForRequest:(NSData *) requestData
                                     withCACertificate:(RadX509Certificate *) caCertificate
                                            privateKey:(RadEVPPKey *) caPrivateKey;
@end

#endif