;; test_commoncrypto.nu
;;
;;  Copyright (c) 2008 Tim Burks, Neon Design Technology, Inc.

(load "RadCrypto")

(class TestCommonCrypto is NuTestCase
     
     (- testHMAC is
	(set data ("data" dataUsingEncoding:NSUTF8StringEncoding))
	(set key ("key" dataUsingEncoding:NSUTF8StringEncoding))
	(set hmac ((data hmacSha1DataWithKey:key) hexEncodedString))
        (assert_equal "104152c5bfdca07bc633eebd46199f0255c9f49d" hmac)))
