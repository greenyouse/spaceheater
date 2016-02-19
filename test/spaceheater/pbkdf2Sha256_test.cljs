(ns spaceheater.pbkdf2Sha256-test
  (:require [cljs.test :as test :refer [test-var]
             :refer-macros [are is deftest]]
            [goog.crypt :as gc]
            [spaceheater.pbkdf2Sha256 :as s :refer [deriveKeySha256]]))

;; test vectors from:
;; https://github.com/bitwiseshiftleft/sjcl/blob/master/test/pbkdf2_test.js
;; https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04#section-11
(deftest deriveKeySha256-test
  (are [expected passwd salt iterations dkLen]
      (= (vec (gc/hexToByteArray expected))
        (vec (deriveKeySha256 (gc/stringToByteArray passwd)
                (gc/stringToByteArray salt) iterations dkLen)))

    "97b5a91d35af542324881315c4f849e327c4707d1bc9d322"
    "password" "xWZ]cË" 2048 192

    "120fb6cffcf8b32c43e7225256c4f837a86548c9"
    "password" "salt" 1 160

    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    "passwd" "salt" 1 512

    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
    "Password" "NaCl"
    80000 512))
