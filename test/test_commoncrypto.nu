;; test_commoncrypto.nu
;;
;;  Copyright (c) 2013 Tim Burks, Radtastical Inc.

(load "RadCrypto")

(class TestCommonCrypto is NuTestCase
 
 (- testHMAC is
    (set data ("data" dataUsingEncoding:NSUTF8StringEncoding))
    (set key ("key" dataUsingEncoding:NSUTF8StringEncoding))
    (assert_equal "9d5c73ef85594d34ec4438b7c97e51d8"
                  ((data hmacMd5DataWithKey:key) hexEncodedString))
    (assert_equal "104152c5bfdca07bc633eebd46199f0255c9f49d"
                  ((data hmacSha1DataWithKey:key) hexEncodedString))
    (assert_equal "19424d4210e50d7a4521b5f0d54b4b0cff3060deddccfd894fda5b3b"
                  ((data hmacSha224DataWithKey:key) hexEncodedString))
    (assert_equal "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
                  ((data hmacSha256DataWithKey:key) hexEncodedString))
    (assert_equal "c5f97ad9fd1020c174d7dc02cf83c4c1bf15ee20ec555b690ad58e62da8a00ee44ccdb65cb8c80acfd127ebee568958a"
                  ((data hmacSha384DataWithKey:key) hexEncodedString))
    (assert_equal "3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58"
                  ((data hmacSha512DataWithKey:key) hexEncodedString)))
 
 (- testHashing is
    (set data ("data" dataUsingEncoding:NSUTF8StringEncoding))
    (assert_equal "8d777f385d3dfec8815d20f7496026dc"
                  ((data md5Data) hexEncodedString))
    (assert_equal "a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd"
                  ((data sha1Data) hexEncodedString))
    (assert_equal "f4739673acc03c424343b452787ee23dd62999a8a9f14f4250995769"
                  ((data sha224Data) hexEncodedString))
    (assert_equal "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
                  ((data sha256Data) hexEncodedString))
    (assert_equal "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
                  ((data sha384Data) hexEncodedString))
    (assert_equal "77c7ce9a5d86bb386d443bb96390faa120633158699c8844c30b13ab0bf92760b7e4416aea397db91b4ac0e5dd56b8ef7e4b066162ab1fdc088319ce6defc876"
                  ((data sha512Data) hexEncodedString)))
 
 (- testAES is
    (set plaintext ("This is a test." dataUsingEncoding:NSUTF8StringEncoding))
    (set key ("This is a key." dataUsingEncoding:NSUTF8StringEncoding))
    (set encrypted (plaintext aesEncryptedDataWithPassword:"password" salt:"salt"))
    (assert_equal "a907700fdc9a7cee0731054e72beb6fd" (encrypted hexEncodedString))
    (set decrypted (encrypted aesDecryptedDataWithPassword:"password" salt:"salt"))
    (assert_equal plaintext decrypted)))







