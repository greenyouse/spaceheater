(ns spaceheater.core
  (:require [goog.crypt :as gc]
            [goog.crypt.hashTester :as gt]
            [goog.crypt.baseN :as gn]
            [spaceheater.scrypt :as s]
            [clojure.string :as cs])
  (:import [goog.crypt Hmac Sha256]
           [goog.math Integer]))

;; TODO: build the hasher here and give an example block
;; to show that it works (test out each fn too, obviously)

;; https://litecoin.info/Block_hashing_algorithm
;; http://explorer.litecoin.net/block/e11049dfa5858be3809f285685e12a5d6f84b936b0f8e8272b5363bf3946ce60


(def bit "01")
(def hex "0123456789abcdef")
(def decimal "0123456789")

(defn hex-endian-swap [hex]
  (-> hex gc/hexToByteArray s/flip-endian gc/byteArrayToHex))

;; TODO: add hex? fn + pre-conditions to verify input type
(defn run-sha256
  "Preforms a Sha256 Hash on a hex value, outputs a hex value"
  [value]
  (let [sha (Sha256.)]
    (.update sha (gc/hexToByteArray value))
    (gc/byteArrayToHex (.digest sha))))

;; something like this should work for hashing blocks
;; need to get scrypt running before I can test through :(
(comment
  (defn block-hasher [ver prev-block merkle timestamp difficulty nonce]
    (let [header-hex (str (hex-endian-swap ver)
                          (hex-endian-swap prev-block)
                          (hex-endian-swap merkle)
                          (hex-endian-swap
                            (gn/recodeString timestamp decimal hex))
                          (hex-endian-swap difficulty)
                          ;; FIXME: this nonce should be generated instead
                          (hex-endian-swap (gn/recodeString nonce decimal hex)))
          header-bin (gn/recodeString header-hex hex bit)
          hash (->> header-hex
                    run-sha256
                    run-sha256
                    hex-endian-swap)
          scrypt-hash (->> (p/scrypt header-hex header-hex 1024 1 1 32)
                           (gc/byteArrayToHex)
                           (hex-endian-swap))]
      scrypt-hash)))

(comment
  (= (block-hasher "00000001" ; version of litecoin software?
        ;; sha256d of the previous block header
        "e29b694e070915c380466c4b101e64f3dffd4bfca3b6cc830efa1b85348917ae"
        ;; sha256d of all transactions in merkle root
        "a959ab3b821f375917c7458befed853b3e084324f97896a537ef99218d2d67bd"
        (subs (str (.now js/Date)) 0 10)  ; current time in seconds
        "1d00d544" ; current litecoin difficulty
       "2147586629") )

  ;; the target value we're trying to solve for
  "e11049dfa5858be3809f285685e12a5d6f84b936b0f8e8272b5363bf3946ce60")
