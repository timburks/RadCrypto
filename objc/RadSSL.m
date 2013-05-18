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

#if !TARGET_OS_IPHONE

// production: gateway.push.apple.com, port 2195
// sandbox:    gateway.sandbox.push.apple.com, port 2195

#import <Foundation/Foundation.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>


#import "RadSSL.h"
#import "RadBinaryEncoding.h"

// Apple is deprecating OpenSSL, but it's not clear what the replacement should be
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

@implementation NSData (RadSSL)

+ (NSData *) dataWithBIO:(BIO *) bio
{
    NSMutableData *data = [NSMutableData new];
    unsigned char buffer[1024];
    for (;;) {
        int bytes = BIO_read(bio, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        [data appendBytes:buffer length:bytes];
    }
    return data;
}
@end


@interface RadSSL ()
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
}

@end

@implementation RadSSL

#define DEVICE_BINARY_SIZE 32
#define MAXPAYLOAD_SIZE 1000

- (id) init {
    if (self = [super init]) {
        // Let's get nice error messages
        SSL_load_error_strings();
        
        // Set up all the global SSL stuff
        OpenSSL_add_ssl_algorithms();
        ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    }
    return self;
}

- (BOOL) __sendPayload:(NSString *) payloadString toDeviceWithToken:(NSString *) deviceTokenString
{
    if (!deviceTokenString) {
        return NO;
    }
    
    NSData *deviceToken = [NSData dataWithBase64EncodedString:deviceTokenString];
    const char *deviceTokenBinary = [deviceToken bytes];
    const char *payloadBuffer = [payloadString cStringUsingEncoding:NSASCIIStringEncoding];
    size_t payloadLength = strlen(payloadBuffer);
    
    if (ssl && deviceTokenBinary && payloadBuffer && payloadLength) {
        NSLog(@"sending %@", payloadString);
        uint8_t command = 0;                      /* command number */
        char binaryMessageBuff[sizeof(uint8_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + MAXPAYLOAD_SIZE];
        // message format is, |COMMAND|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD|
        char *binaryMessagePt = binaryMessageBuff;
        uint16_t networkOrderTokenLength = htons([deviceToken length]);
        uint16_t networkOrderPayloadLength = htons(payloadLength);
        
        // command
        *binaryMessagePt++ = command;
        
        // token length network order
        memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(uint16_t));
        binaryMessagePt += sizeof(uint16_t);
        
        // device token
        memcpy(binaryMessagePt, deviceTokenBinary, [deviceToken length]);
        binaryMessagePt += [deviceToken length];
        
        // payload length network order
        memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
        binaryMessagePt += sizeof(uint16_t);
        
        // payload
        memcpy(binaryMessagePt, payloadBuffer, payloadLength);
        binaryMessagePt += payloadLength;
        
        // send it
        if (SSL_write(ssl, binaryMessageBuff, (int) (binaryMessagePt - binaryMessageBuff)) > 0) {
            return YES;
        }
    }
    NSLog(@"send failed");
    return NO;
}

- (BOOL) sendPayload:(NSString *) payloadString toDeviceWithToken:(NSString *) deviceTokenString
{
    if (!deviceTokenString) {
        return NO;
    }
    
    NSData *deviceToken = [NSData dataWithBase64EncodedString:deviceTokenString];
    const char *deviceTokenBinary = [deviceToken bytes];
    const char *payloadBuffer = [payloadString cStringUsingEncoding:NSASCIIStringEncoding];
    size_t payloadLength = strlen(payloadBuffer);
    bool rtn = false;
    if (ssl && deviceTokenBinary && payloadBuffer && payloadLength)
    {
        uint8_t command = 1; /* command number */
        char binaryMessageBuff[sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) +
                               DEVICE_BINARY_SIZE + sizeof(uint16_t) + MAXPAYLOAD_SIZE];
        /* message format is, |COMMAND|ID|EXPIRY|TOKENLEN|TOKEN|PAYLOADLEN|PAYLOAD| */
        char *binaryMessagePt = binaryMessageBuff;
        uint32_t whicheverOrderIWantToGetBackInAErrorResponse_ID = 1234;
        uint32_t networkOrderExpiryEpochUTC = htonl(time(NULL)+86400); // expire message if not delivered in 1 day
        uint16_t networkOrderTokenLength = htons(DEVICE_BINARY_SIZE);
        uint16_t networkOrderPayloadLength = htons(payloadLength);
        
        /* command */
        *binaryMessagePt++ = command;
        
        /* provider preference ordered ID */
        memcpy(binaryMessagePt, &whicheverOrderIWantToGetBackInAErrorResponse_ID, sizeof(uint32_t));
        binaryMessagePt += sizeof(uint32_t);
        
        /* expiry date network order */
        memcpy(binaryMessagePt, &networkOrderExpiryEpochUTC, sizeof(uint32_t));
        binaryMessagePt += sizeof(uint32_t);
        
        /* token length network order */
        memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(uint16_t));
        binaryMessagePt += sizeof(uint16_t);
        
        /* device token */
        memcpy(binaryMessagePt, deviceTokenBinary, DEVICE_BINARY_SIZE);
        binaryMessagePt += DEVICE_BINARY_SIZE;
        
        /* payload length network order */
        memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
        binaryMessagePt += sizeof(uint16_t);
        
        /* payload */
        memcpy(binaryMessagePt, payloadBuffer, payloadLength);
        binaryMessagePt += payloadLength;
        if (SSL_write(ssl, binaryMessageBuff, (int) (binaryMessagePt - binaryMessageBuff)) > 0)
            rtn = true;
    }
    return rtn;
}

- (void) read {
    unsigned char buffer[1024];
    memset(buffer, 0, 1024);
    int i = SSL_read(ssl, buffer, 1024);
    buffer[1023] = 0;
    NSLog(@"read %d", i);
    for (int j = 0; j < i; j++) {
        NSLog(@"%d: %d", j, buffer[j]);
    }
}

- (void) setCAListFileName:(NSString *)CAListFileName {
    NSData *cert_data = [NSData dataWithContentsOfFile:CAListFileName];
    [self setCAListData:cert_data];
}

- (void) setCAListData:(NSData *) cert_data
{
    X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_ctx);
    const unsigned char *bytes = [cert_data bytes];
    X509 *cert = d2i_X509(0, &bytes, [cert_data length]);
    X509_STORE_add_cert(cert_store, cert);
}

- (void) setCAListText:(NSString *) cert_string
{
    BIO *buffer = BIO_new(BIO_s_mem());
    X509 *cert = NULL;
    BIO_reset(buffer);
    if(BIO_write(buffer,
                 [cert_string cStringUsingEncoding:NSUTF8StringEncoding],
                 (int) [cert_string length]) != [cert_string length])
        NSLog(@"error feeding buffer");
    if(PEM_read_bio_X509(buffer,&cert,0,NULL)) {
        X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_ctx);
        X509_STORE_add_cert(cert_store, cert);
    }
}

- (void) setCertificateFileName:(NSString *)certificateFileName {
    NSData *cert_data = [NSData dataWithContentsOfFile:certificateFileName];
    [self setCertificateData:cert_data];
}

- (void) setCertificateData:(NSData *) cert_data
{
    const unsigned char *bytes = [cert_data bytes];
    X509 *cert = d2i_X509(0, &bytes, [cert_data length]);
    SSL_CTX_use_certificate(ssl_ctx, cert);
}

- (void) setCertificateText:(NSString *) cert_string
{
    BIO *buffer = BIO_new(BIO_s_mem());
    X509 *cert = NULL;
    BIO_reset(buffer);
    if(BIO_write(buffer,
                 [cert_string cStringUsingEncoding:NSUTF8StringEncoding],
                 (int) [cert_string length]) != [cert_string length])
        NSLog(@"error feeding buffer");
    if(PEM_read_bio_X509(buffer,&cert,0,NULL)) {
        SSL_CTX_use_certificate(ssl_ctx, cert);
    }
}

- (void) setKeyFileName:(NSString *)keyFileName
{
    [self setKeyData:[NSData dataWithContentsOfFile:keyFileName]];
}

- (void) setKeyData:(NSData *) key_data
{
    const unsigned char *bytes = [key_data bytes];
    RSA *pkey = d2i_RSAPrivateKey(NULL, &bytes, [key_data length]);
    SSL_CTX_use_RSAPrivateKey(ssl_ctx, pkey);
}

- (void) setKeyText:(NSString *) key_string
{
    BIO *buffer = BIO_new(BIO_s_mem());
    RSA *pkey = NULL;
    BIO_reset(buffer);
    if(BIO_write(buffer,
                 [key_string cStringUsingEncoding:NSUTF8StringEncoding],
                 (int) [key_string length]) != [key_string length])
        NSLog(@"error feeding buffer");
    if(PEM_read_bio_RSAPrivateKey(buffer,&pkey,0,NULL)) {
        SSL_CTX_use_RSAPrivateKey(ssl_ctx, pkey);
    }
}


- (void) connectToHost:(NSString *) host port:(int) port
{
    const char *hostAndPort = [[NSString stringWithFormat:@"%@:%d", host, port]
                               cStringUsingEncoding:NSASCIIStringEncoding];
    BIO *conn = BIO_new_connect((char *) hostAndPort);
    if (!conn) {
        NSLog(@"Can't create connection");
        return;
    }
    
    if (BIO_do_connect(conn) <= 0) {
        NSLog(@"failed to connect");
        return;
    }
    
    ssl = SSL_new(ssl_ctx);
    SSL_set_bio(ssl, conn, conn);
    
    if (SSL_connect(ssl) <= 0) {
        NSLog(@"error connecting SSL object");
        return;
    }
    NSLog(@"connected");
}

- (void) closeConnection {
    SSL_shutdown(ssl);
    SSL_clear(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
}

@end

@implementation RadRSAKey

- (id) initWithPrivateKeyData:(NSData *) key_data
{
    if (self = [super init]) {
        const unsigned char *bytes = [key_data bytes];
        rsa = d2i_RSAPrivateKey(NULL, &bytes, [key_data length]);
        //SSL_CTX_use_RSAPrivateKey(ssl_ctx, rsaKey);
    }
    return self;
}

- (id) initWithPrivateKeyText:(NSString *) key_string
{
    if (self = [super init]) {
        BIO *buffer = BIO_new(BIO_s_mem());
        rsa = NULL;
        BIO_reset(buffer);
        if(BIO_write(buffer,
                     [key_string cStringUsingEncoding:NSUTF8StringEncoding],
                     (int) [key_string length]) != [key_string length])
            NSLog(@"error feeding buffer");
        if(PEM_read_bio_RSAPrivateKey(buffer,&rsa,0,NULL)) {
            //SSL_CTX_use_RSAPrivateKey(ssl_ctx, rsa);
            NSLog(@"got it");
        } else {
            NSLog(@"didn't get it");
        }
    }
    return self;
}

- (int) checkKey {
    return RSA_check_key(rsa);
}

@end

@implementation RadEVPPKey

- (id) initWithRSAKey:(RadRSAKey *) rsaKey
{
    if (self = [super init]) {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsaKey->rsa);
    }
    return self;
}
@end

@implementation RadX509Request

- (id) init {
    if (self = [super init]) {
        req = X509_REQ_new();
    }
    return self;
}


@end

@implementation RadX509Certificate

- (id) initWithData:(NSData *) cert_data
{
    if (self = [super init]) {
        const unsigned char *bytes = [cert_data bytes];
        cert = d2i_X509(0, &bytes, [cert_data length]);
        //   SSL_CTX_use_certificate(ssl_ctx, cert);
    }
    return self;
}

- (id) initWithText:(NSString *) cert_string
{
    if (self = [super init]) {
        BIO *buffer = BIO_new(BIO_s_mem());
        cert = NULL;
        BIO_reset(buffer);
        if(BIO_write(buffer,
                     [cert_string cStringUsingEncoding:NSUTF8StringEncoding],
                     (int) [cert_string length]) != [cert_string length])
            NSLog(@"error feeding buffer");
        if(PEM_read_bio_X509(buffer,&cert,0,NULL)) {
            //  SSL_CTX_use_certificate(ssl_ctx, cert);
            NSLog(@"got it");
        } else {
            NSLog(@"didn't get it");
        }
    }
    return self;
}

- (id) initWithX509:(X509 *) x509
{
    if (self = [super init]) {
        self->cert = x509;
    }
    return self;
}

- (NSString *) name
{
    X509_NAME *name = X509_get_subject_name(cert);
    BIO *bio = BIO_new(BIO_s_mem());
    X509_NAME_print(bio, name, 0);
    
    NSData *data = [NSData dataWithBIO:bio];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSData *) dataRepresentation
{
    BIO *bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio, self->cert);
    return [NSData dataWithBIO:bio];
}

- (NSString *) textRepresentation
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, self->cert);
    return [[NSString alloc] initWithData:[NSData dataWithBIO:bio] encoding:NSUTF8StringEncoding];
}

@end

/* OpenSSL OID handles */
int nid_messageType;
int nid_pkiStatus;
int nid_failInfo;
int nid_senderNonce;
int nid_recipientNonce;
int nid_transId;
int nid_extensionReq;

@implementation RadPKCS7Message

+ (void) initialize
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings (); // redundant?
    
    nid_messageType    = OBJ_create("2.16.840.1.113733.1.9.2", "messageType", "messageType");
    nid_pkiStatus      = OBJ_create("2.16.840.1.113733.1.9.3", "pkiStatus", "pkiStatus");
    nid_failInfo       = OBJ_create("2.16.840.1.113733.1.9.4", "failInfo", "failInfo");
    nid_senderNonce    = OBJ_create("2.16.840.1.113733.1.9.5", "senderNonce","senderNonce");
    nid_recipientNonce = OBJ_create("2.16.840.1.113733.1.9.6", "recipientNonce", "recipientNonce");
    nid_transId        = OBJ_create("2.16.840.1.113733.1.9.7", "transId", "transId");
    nid_extensionReq   = OBJ_create("2.16.840.1.113733.1.9.8", "extensionReq", "extensionReq");
}

int add_attribute_string(STACK_OF(X509_ATTRIBUTE) *attrs, int nid, char *buffer) {
    ASN1_STRING     *asn1_string = NULL;
    X509_ATTRIBUTE  *x509_a;
    int             c;
    
    asn1_string = ASN1_STRING_new();
    if ((c = ASN1_STRING_set(asn1_string, buffer, (int) strlen(buffer))) <= 0) {
        fprintf(stderr, "error adding data to ASN.1 string\n");
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_PRINTABLESTRING, asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

int add_attribute_octet(STACK_OF(X509_ATTRIBUTE) *attrs, int nid, char *buffer,
                        int len) {
    ASN1_STRING     *asn1_string = NULL;
    X509_ATTRIBUTE  *x509_a;
    int             c;
    
    asn1_string = ASN1_STRING_new();
    if ((c = ASN1_STRING_set(asn1_string, buffer, len)) <= 0) {
        fprintf(stderr, "error adding data to ASN.1 string\n");
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_OCTET_STRING, asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

+ (RadPKCS7Message *) signedMessageWithCertificate:(RadX509Certificate *) certificate
                                        privateKey:(RadEVPPKey *) key
                                              data:(NSData *) dataToSign
                                  signedAttributes:(NSDictionary *) signedAttributes
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_reset(bio);
    if(BIO_write(bio,
                 [dataToSign bytes],
                 (int) [dataToSign length]) != [dataToSign length])
        NSLog(@"error feeding buffer");
    
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_add_certificate(p7, certificate->cert);
    PKCS7_SIGNER_INFO *si = PKCS7_add_signature(p7, certificate->cert, key->pkey, EVP_md5());
    unsigned long len = [dataToSign length];
    
    /* Set signed attributes */
    STACK_OF(X509_ATTRIBUTE) *attributes = sk_X509_ATTRIBUTE_new_null();
    id value;
    if ((value = [signedAttributes objectForKey:@"pkiStatus"])) {
        add_attribute_string(attributes, nid_pkiStatus, (char *) [value cStringUsingEncoding:NSUTF8StringEncoding]);
    }
    if ((value = [signedAttributes objectForKey:@"transactionID"])) {
        add_attribute_string(attributes, nid_transId, (char *) [value cStringUsingEncoding:NSUTF8StringEncoding]);
    }
    if ((value = [signedAttributes objectForKey:@"messageType"])) {
        add_attribute_string(attributes, nid_messageType, (char *) [value cStringUsingEncoding:NSUTF8StringEncoding]);
    }
    if ((value = [signedAttributes objectForKey:@"senderNonce"])) {
        add_attribute_octet(attributes, nid_senderNonce, (char *) [value bytes], (int) [value length]);
    }
    if ((value = [signedAttributes objectForKey:@"recipientNonce"])) {
        add_attribute_octet(attributes, nid_recipientNonce, (char *) [value bytes], (int) [value length]);
    }
    PKCS7_set_signed_attributes(si, attributes);
    
    /* Add contentType */
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                    V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data))) {
        fprintf(stderr, "error adding NID_pkcs9_contentType\n");
    }
    
    /* Create new content */
    if (!PKCS7_content_new(p7, NID_pkcs7_data)) {
        fprintf(stderr, "failed setting PKCS#7 content type\n");
    }
    
    /* Write data  */
    BIO *pkcs7bio = PKCS7_dataInit(p7, NULL);
    if (pkcs7bio == NULL) {
        fprintf(stderr, "error opening bio for writing PKCS#7 data\n");
    }
    if (len != (unsigned long) BIO_write(pkcs7bio, bio, (int) len)) {
        fprintf(stderr, "error writing PKCS#7 data\n");
    }
    
    /* Finalize PKCS#7  */
    if (!PKCS7_dataFinal(p7, pkcs7bio)) {
        fprintf(stderr, "error finalizing outer PKCS#7\n");
    }
    
    return [[RadPKCS7Message alloc] initWithPKCS7:p7];
}

+ (RadPKCS7Message *) degenerateWrapperForCertificate:(RadX509Certificate *) certificate
{
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_add_certificate(p7, certificate->cert);
    return [[RadPKCS7Message alloc] initWithPKCS7:p7];
}

+ (RadPKCS7Message *) encryptedMessageWithCertificates:(NSArray *) certificates
                                                  data:(NSData *) dataToEncrypt {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_reset(bio);
    if(BIO_write(bio,
                 [dataToEncrypt bytes],
                 (int) [dataToEncrypt length]) != [dataToEncrypt length])
        NSLog(@"error feeding buffer");
    const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
    STACK_OF(X509) *certs = sk_X509_new_null();
    for (RadX509Certificate *certificate in certificates) {
        sk_X509_push(certs, certificate->cert);
    }
    PKCS7 *p7 = PKCS7_encrypt(certs, bio, cipher, 0);
    return [[RadPKCS7Message alloc] initWithPKCS7:p7];
}

- (id) initWithData:(NSData *) data
{
    if (self = [super init]) {
        BIO *buffer = BIO_new(BIO_s_mem());
        BIO_reset(buffer);
        if(BIO_write(buffer,
                     [data bytes],
                     (int) [data length]) != [data length])
            NSLog(@"error feeding buffer");
        p7 = d2i_PKCS7_bio(buffer, NULL);
        if (!p7) {
            NSLog(@"error parsing pkcs7");
        }
    }
    return self;
}

- (id) initWithPKCS7:(PKCS7 *) pkcs7 {
    if (self = [super init]) {
        self->p7 = pkcs7;
    }
    return self;
}

- (NSData *) dataRepresentation
{
    BIO *bio = BIO_new(BIO_s_mem());
    i2d_PKCS7_bio(bio, p7);
    return [NSData dataWithBIO:bio];
}

- (NSString *) textRepresentation
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS7(bio, p7);
    return [[NSString alloc] initWithData:[NSData dataWithBIO:bio] encoding:NSUTF8StringEncoding];
}

/*
 PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data, int flags);
 STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs, int flags);
 PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher, int flags);
 */

- (NSData *) decryptWithKey:(RadEVPPKey *) key
                certificate:(RadX509Certificate *) certificate
{
    if (!PKCS7_type_is_encrypted(p7)) {
        NSLog(@"pkcs7 is not encrypted");
    }
    
    BIO *data = BIO_new(BIO_s_mem());
    int status = PKCS7_decrypt(p7, key->pkey, certificate->cert, data, 0);
    NSLog(@"decrypt status %d", status);
    if (!status) {
        SSL_load_error_strings();
        unsigned long error = ERR_get_error();
        char buf[120];
        NSLog(@"error %ld: %s reason=>%s", error, ERR_error_string(error, buf), ERR_reason_error_string(error));
        return nil;
    } else {
        NSData *decryptedData = [NSData dataWithBIO:data];
        NSLog(@"PKCS#7 contains %ld bytes of decrypted data", (unsigned long) [decryptedData length]);
        return decryptedData;
    }
}

int get_attribute(STACK_OF(X509_ATTRIBUTE) *attribs, int required_nid, ASN1_TYPE **asn1_type) {
    int             i;
    ASN1_OBJECT     *asn1_obj = NULL;
    X509_ATTRIBUTE  *x509_attrib = NULL;
    int v_flag = 1;
    if (v_flag)
        NSLog(@"finding attribute %s\n",
              OBJ_nid2sn(required_nid));
    *asn1_type = NULL;
    asn1_obj = OBJ_nid2obj(required_nid);
    if (asn1_obj == NULL) {
        NSLog(@"error creating ASN.1 object\n");
        ERR_print_errors_fp(stderr);
    }
    /* Find attribute */
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attribs); i++) {
        x509_attrib = sk_X509_ATTRIBUTE_value(attribs, i);
        if (OBJ_cmp(x509_attrib->object, asn1_obj) == 0) {
            if ((x509_attrib->value.set) &&
                (sk_ASN1_TYPE_num(x509_attrib->value.set) != 0)) {
                if (*asn1_type != NULL) {
                    NSLog(@"no value found");
                }
                *asn1_type = sk_ASN1_TYPE_value(x509_attrib->value.set, 0);
            }
        }
    }
    
    if (*asn1_type == NULL)
        return (1);
    return (0);
}

/* Find signed attributes */
int get_signed_attribute(STACK_OF(X509_ATTRIBUTE) *attribs, int nid, int type, char **buffer) {
    int             rc;
    ASN1_TYPE       *asn1_type;
    unsigned int    len;
    int v_flag = 1;
    /* Find attribute */
    rc = get_attribute(attribs, nid, &asn1_type);
    if (rc == 1) {
        return (1);
    }
    if (ASN1_TYPE_get(asn1_type) != type) {
        NSLog(@"wrong ASN.1 type");
    }
    
    /* Copy data */
    len = ASN1_STRING_length(asn1_type->value.asn1_string);
    if (len <= 0) {
        return (1);
    } else if (v_flag)
        NSLog(@"allocating %d bytes for attribute", len);
    if (type == V_ASN1_PRINTABLESTRING) {
        *buffer = (char *)malloc(len + 1);
    } else {
        *buffer = (char *)malloc(len);
    }
    if (*buffer == NULL) {
        NSLog(@"cannot malloc space for attribute");
    }
    memcpy(*buffer, ASN1_STRING_data(asn1_type->value.asn1_string), len);
    
    /* Add null terminator if it's a PrintableString */
    if (type == V_ASN1_PRINTABLESTRING) {
        (*buffer)[len] = 0;
        len++;
    }
    
    return (0);
}


X509 *My_PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si)
{
    if (PKCS7_type_is_signed(p7))
        return(X509_find_by_issuer_and_serial(p7->d.sign->cert,
                                              si->issuer_and_serial->issuer,
                                              si->issuer_and_serial->serial));
    else if (PKCS7_type_is_signedAndEnveloped(p7))
        return(X509_find_by_issuer_and_serial(p7->d.signed_and_enveloped->cert,
                                              si->issuer_and_serial->issuer,
                                              si->issuer_and_serial->serial));
    else {
        NSLog (@"no cert");
        return NULL;
    }
}

- (RadX509Certificate *) signerCertificate {
    if (!PKCS7_type_is_signed(p7)) {
		NSLog(@"PKCS#7 is not signed!");
		ERR_print_errors_fp(stderr);
        return nil;
    }
    STACK_OF(PKCS7_SIGNER_INFO)	*sk;
    sk = PKCS7_get_signer_info(p7);
    
    PKCS7_SIGNER_INFO		*si;
    si = sk_PKCS7_SIGNER_INFO_value(sk, 0);
    
    X509 *signer_cert = My_PKCS7_cert_from_signer_info(p7, si);
    assert(signer_cert);
    
    return [[RadX509Certificate alloc] initWithX509:signer_cert];
}

- (NSDictionary *) attributes {
    
    // Make sure this is a signed PKCS#7
    if (!PKCS7_type_is_signed(p7)) {
		NSLog(@"PKCS#7 is not signed!");
		ERR_print_errors_fp(stderr);
        return nil;
    }
    STACK_OF(PKCS7_SIGNER_INFO)	*sk = PKCS7_get_signer_info(p7);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk, 0);
    X509 *signer_cert = My_PKCS7_cert_from_signer_info(p7, si);
    assert(signer_cert);
    
    NSMutableDictionary *attributeDictionary = [NSMutableDictionary dictionary];
    
    char *p;
    STACK_OF(X509_ATTRIBUTE) *attributes = PKCS7_get_signed_attributes(si);
    if ((get_signed_attribute(attributes, nid_messageType,
                              V_ASN1_PRINTABLESTRING, &p)) == 1) {
        NSLog(@"cannot find messageType");
    } else {
        [attributeDictionary setObject:[NSString stringWithCString:p encoding:NSUTF8StringEncoding]
                                forKey:@"messageType"];
    }
    
    if ((get_signed_attribute(attributes, nid_transId,
                              V_ASN1_PRINTABLESTRING, &p)) == 1) {
        NSLog(@"cannot find transId");
    } else {
        [attributeDictionary setObject:[NSString stringWithCString:p encoding:NSUTF8StringEncoding]
                                forKey:@"transactionID"];
    }
    
    if ((get_signed_attribute(attributes, nid_senderNonce,
                              V_ASN1_OCTET_STRING, &p)) == 1) {
        NSLog(@"cannot find nid_senderNonce");
    } else {
        NSData *senderNonce = [NSData dataWithBytes:p length:sizeof(p)];
        [attributeDictionary setObject:senderNonce forKey:@"senderNonce"];
    }
    
    if ((get_signed_attribute(attributes, nid_recipientNonce,
                              V_ASN1_OCTET_STRING, &p)) == 1) {
        NSLog(@"cannot find nid_recipientNonce");
    } else {
        NSData *recipientNonce = [NSData dataWithBytes:p length:sizeof(p)];
        [attributeDictionary setObject:recipientNonce forKey:@"recipientNonce"];
    }
    
    if ((get_signed_attribute(attributes, nid_pkiStatus,
                              V_ASN1_PRINTABLESTRING, &p)) == 1) {
        NSLog(@"cannot find nid_pkiStatus");
    } else {
        NSLog(@"nid_pkiStatus: %s", p);
        [attributeDictionary setObject:[NSString stringWithCString:p encoding:NSUTF8StringEncoding]
                                forKey:@"pkiStatus"];
    }
    return attributeDictionary;
}


- (NSData *) verifyWithCertificate:(RadX509Certificate *) certificate
{
    // Make sure this is a signed PKCS#7
    if (!PKCS7_type_is_signed(p7)) {
		NSLog(@"PKCS#7 is not signed!");
		ERR_print_errors_fp(stderr);
        return nil;
    }
    STACK_OF(PKCS7_SIGNER_INFO)	*sk = PKCS7_get_signer_info(p7);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk, 0);
    X509 *signer_cert = My_PKCS7_cert_from_signer_info(p7, si);
    assert(signer_cert);
    
    /* Create BIO for content data */
	BIO *pkcs7bio = PKCS7_dataInit(p7, NULL);
	if (pkcs7bio == NULL) {
		NSLog(@"@@@ cannot get PKCS#7 data");
		ERR_print_errors_fp(stderr);
		return nil;
	}
    
    /* Copy enveloped data from PKCS#7 */
    NSData *envelopedData = [NSData dataWithBIO:pkcs7bio];
    NSLog(@"PKCS#7 contains %ld bytes of enveloped data", (unsigned long) [envelopedData length]);
    
    if (PKCS7_signatureVerify(pkcs7bio, p7, si, signer_cert) <= 0) {
		NSLog(@"error verifying signature");
		ERR_print_errors_fp(stderr);
        return nil;
	} else {
        NSLog(@"signature verified");
    }
    
    return envelopedData;
}
@end

@implementation RadCertificateAuthority
void
handle_error (const char *file, int lineno, const char *msg)
{
    fprintf (stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp (stderr);
    exit (-1);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

#define DAYS_TILL_EXPIRE 365
#define EXPIRE_SECS (60*60*24*DAYS_TILL_EXPIRE)

#define EXT_COUNT 5

struct entry
{
    char *key;
    char *value;
};

struct entry ext_ent[EXT_COUNT] = {
    {"basicConstraints", "CA:FALSE"},
    {"nsComment", "\"OpenSSL Generated Certificate\""},
    {"subjectKeyIdentifier", "hash"},
    {"authorityKeyIdentifier", "keyid,issuer:always"},
    {"keyUsage", "nonRepudiation,digitalSignature,keyEncipherment"}
};

- (RadX509Certificate *) generateCertificateForRequest:(NSData *) requestData
                                     withCACertificate:(RadX509Certificate *) caCertificate
                                            privateKey:(RadEVPPKey *) caPrivateKey
{
    int i, subjAltName_pos;
    long serial = 1;
    EVP_PKEY *pkey, *CApkey;
    const EVP_MD *digest;
    X509 *cert, *CAcert;
    X509_NAME *name;
    X509V3_CTX ctx;
    X509_EXTENSION *subjAltName;
    STACK_OF (X509_EXTENSION) * req_exts;
    
    const unsigned char *bytes = [requestData bytes];
    X509_REQ *req = d2i_X509_REQ(0, &bytes, [requestData length]);
    
    /* verify signature on the request */
    if (!(pkey = X509_REQ_get_pubkey (req)))
        int_error ("Error getting public key from request");
    if (X509_REQ_verify (req, pkey) != 1)
        int_error ("Error verifying signature on certificate");
    
    CAcert = caCertificate->cert;
    CApkey = caPrivateKey->pkey;
    
    /* print out the subject name and subject alt name extension */
    if (!(name = X509_REQ_get_subject_name (req)))
        int_error ("Error getting subject name from request");
    
    if (!(req_exts = X509_REQ_get_extensions (req)))
        int_error ("Error getting the request's extensions");
    
    subjAltName_pos = X509v3_get_ext_by_NID (req_exts,
                                             OBJ_sn2nid ("subjectAltName"), -1);
    subjAltName = X509v3_get_ext (req_exts, subjAltName_pos);
    if (!subjAltName) {
        NSLog(@"alt name is not found");
    }
    
    /* WE SHOULD NOW ASK WHETHER TO CONTINUE OR NOT */
    
    /* create new certificate */
    if (!(cert = X509_new ()))
        int_error ("Error creating X509 object");
    
    /* set version number for the certificate (X509v3) and the serial number */
    if (X509_set_version (cert, 2L) != 1)
        int_error ("Error settin certificate version");
    ASN1_INTEGER_set (X509_get_serialNumber (cert), serial++);
    
    /* set issuer and subject name of the cert from the req and the CA */
    if (!(name = X509_REQ_get_subject_name (req)))
        int_error ("Error getting subject name from request");
    if (X509_set_subject_name (cert, name) != 1)
        int_error ("Error setting subject name of certificate");
    if (!(name = X509_get_subject_name (CAcert)))
        int_error ("Error getting subject name from CA certificate");
    if (X509_set_issuer_name (cert, name) != 1)
        int_error ("Error setting issuer name of certificate");
    
    /* set public key in the certificate */
    if (X509_set_pubkey (cert, pkey) != 1)
        int_error ("Error setting public key of the certificate");
    
    /* set duration for the certificate */
    if (!(X509_gmtime_adj (X509_get_notBefore (cert), 0)))
        int_error ("Error setting beginning time of the certificate");
    if (!(X509_gmtime_adj (X509_get_notAfter (cert), EXPIRE_SECS)))
        int_error ("Error setting ending time of the certificate");
    
    /* add x509v3 extensions as specified */
    X509V3_set_ctx (&ctx, CAcert, cert, NULL, NULL, 0);
    for (i = 0; i < EXT_COUNT; i++)
    {
        X509_EXTENSION *ext;
        if (!(ext = X509V3_EXT_conf (NULL, &ctx,
                                     ext_ent[i].key, ext_ent[i].value)))
        {
            fprintf (stderr, "Error on \"%s = %s\"\n",
                     ext_ent[i].key, ext_ent[i].value);
            int_error ("Error creating X509 extension object");
        }
        if (!X509_add_ext (cert, ext, -1))
        {
            fprintf (stderr, "Error on \"%s = %s\"\n",
                     ext_ent[i].key, ext_ent[i].value);
            int_error ("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free (ext);
    }
    
    if (subjAltName) {
        /* add the subjectAltName in the request to the cert */
        if (!X509_add_ext (cert, subjAltName, -1))
            int_error ("Error adding subjectAltName to certificate");
    }
    
    /* sign the certificate with the CA private key */
    if (EVP_PKEY_type (CApkey->type) == EVP_PKEY_DSA)
        digest = EVP_dss1 ();
    else if (EVP_PKEY_type (CApkey->type) == EVP_PKEY_RSA)
        digest = EVP_sha1 ();
    else {
        int_error ("Error checking CA private key for a valid digest");
        return nil;
    }
    if (!(X509_sign (cert, CApkey, digest))) {
        int_error ("Error signing certificate");
        return nil;
    }
    return [[RadX509Certificate alloc] initWithX509:cert];
}

@end

#endif
