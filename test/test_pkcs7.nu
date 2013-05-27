;; test_pkcs7.nu
;;
;;  Copyright (c) 2013 Tim Burks, Radtastical Inc.

(load "RadCrypto")

(class TestPKCS7 is NuTestCase
 
 (- testSigning is
    (set messageToSign (dict alphabet:"abcdefghijklmnopqrstuvwxyz"
                             integers:(array 0 1 2 3 4 5 6 7 8 9)))
    (set dataToSign (messageToSign XMLPropertyListRepresentation))
    (set certificate ((RadX509Certificate alloc) initWithText:(NSString stringWithContentsOfFile:"test/test.crt")))
    (set key ((RadEVPPKey alloc) initWithRSAKey:((RadRSAKey alloc) initWithPrivateKeyText:(NSString stringWithContentsOfFile:"test/test.key"))))
    (set pkcs7 (RadPKCS7Message signedMessageWithCertificate:certificate
                                                  privateKey:key
                                                        data:dataToSign))
    (set signedData (pkcs7 verifyWithCertificate:certificate))
    (set signedMessage (signedData propertyListValue))
    (assert_equal messageToSign signedMessage))
 
 (- testEncryption is
    (set messageToEncrypt (dict alphabet:"abcdefghijklmnopqrstuvwxyz"
                                integers:(array 0 1 2 3 4 5 6 7 8 9)))
    (set dataToEncrypt (messageToEncrypt XMLPropertyListRepresentation))
    (set certificate ((RadX509Certificate alloc) initWithText:(NSString stringWithContentsOfFile:"test/test.crt")))
    (set key ((RadEVPPKey alloc) initWithRSAKey:((RadRSAKey alloc) initWithPrivateKeyText:(NSString stringWithContentsOfFile:"test/test.key"))))
    (set pkcs7 (RadPKCS7Message encryptedMessageWithCertificates:(array certificate)
                                                            data:dataToEncrypt))    
    (set decryptedData (pkcs7 decryptWithKey:key certificate:certificate))
    (set decryptedMessage (decryptedData propertyListValue))
    (assert_equal messageToEncrypt decryptedMessage)))