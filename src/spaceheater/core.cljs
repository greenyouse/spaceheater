(ns spaceheater.core
  (:require [goog.crypt.base64 :as b]
            [goog.crypt.pbkdf2 :as p]
            [goog.crypt :as gc]
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
