;; test_x509.nu
;;
;;  Copyright (c) 2013 Tim Burks, Radtastical Inc.

(load "RadCrypto")

(class TestX509 is NuTestCase
 
 (- testNames is
    (set certificate ((RadX509Certificate alloc) initWithText:(NSString stringWithContentsOfFile:"test/test.crt")))
    (set gold "C=US, ST=California, L=Palo Alto, O=Radtastical Inc, OU=RadCrypto Unit Tests, CN=radtastical.com/emailAddress=tim@radtastical.com")
    (set name (certificate name))
    (set issuer (certificate issuer))
    (assert_equal gold name)
    (assert_equal gold issuer)))