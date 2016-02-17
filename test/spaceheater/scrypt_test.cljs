(ns spaceheater.scrypt-test
  (:require [cljs.test :as test :refer [test-var]
             :refer-macros [are is deftest]]
            [goog.crypt :as gc]
            [spaceheater.scrypt :as s]))

;; TODO: get these tests working, each fn should be correct
;; not sure why they're failing right now...
;; salsa 20/8 test vectors
;; https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04#section-8
(deftest salsa-20-8-test []
  (are [expected in]
      (= expected
         (gc/byteArrayToHex (s/salsa-20-8 (gc/hexToByteArray in))))
    "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81"
    "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e"))

(deftest blockmix-test
  (are [expected BY]
      (= (map gc/byteArrayToHex expected)
        (s/blockmix-salsa8 (map gc/hexToByteArray in) 0 128 1))

    #js ["a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81"
 "20edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b77d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425"]
    #js ["f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7"
     "894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89"]))

(deftest smix-test
  (are [expected B]
      (= (gc/byteArrayToHex expected)
         (s/smix (gc/hexToByteArray B) 1 16))

    "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e9"
    "79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4be"))

(deftest scrypt-test
  (are [expected P S N r p dklen]
      (= expected
         (s/scrypt P S N r p dklen))

    "6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa"
    "salt" "password" 2 1 1 32

    "6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa"
    "salt" "password" 2 1 1 32

    "6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa"
    "saltSALTsaltSALTsaltSALTsaltSALTsalt" "passwordPASSWORDpassword"
    2 1 1 32

    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc060"
    "password" "NaCl" 1024 8 16 64

    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d1896"
    "" "" 16 1 1 64

    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    "pleaseletmein" "SodiumChloride" 16384  8 1 64

    "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"
    "pleaseletmein" "SodiumChloride" 1048576 8 1 64))
