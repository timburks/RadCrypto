;; test_uuid.nu
;;  tests for the Nu UUID wrapper.
;;
;;  Copyright (c) 2008 Tim Burks, Neon Design Technology, Inc.

(load "RadCrypto")

(class TestUUID is NuTestCase
     
     (- testSimple is
	(set uuid1 ((RadUUID alloc) init))
	(set uuid2 ((RadUUID alloc) init))
        (assert_not_equal uuid1 uuid2)
        (assert_not_equal (uuid1 stringValue) (uuid2 stringValue))
        (assert_equal 36 ((uuid1 stringValue) length))
        (assert_equal 36 ((uuid2 stringValue) length))))
