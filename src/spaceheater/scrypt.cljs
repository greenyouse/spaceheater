(ns spaceheater.scrypt
  "An implementation of the scrypt algorithm based on the spec:
  https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04,
  https://github.com/bitwiseshiftleft/sjcl, and
  http://www.tarsnap.com/scrypt/scrypt.pdf"
  (:require-macros [spaceheater.macros :as m :refer [forloop]]))

;; alaiasing some heavily used functions with long names here
;; to make things a little less verbose (using JS like syntax)
(def xor
  bit-xor)

(def |
  bit-or)

(def b&
  bit-and)

(def <<
  bit-shift-left)

(def >>>
  bit-shift-right-zero-fill)

(defn xor=
  "Does a bitwise xor at that index of the array with the
  given argument and sets that as the new value for index."
  [array index arg]
  (let [i (aget array index)]
    (aset array index (xor i arg))))

(defn flip-endian
  "Takes an integer n and flips the endianness of its bits"
  [n]
  (let [first (b& n 255)
        second (b& (>>> n 8) 255)
        third (b& (>>> n 16) 255)
        fourth (b& (>>> n 24) 255)]
    (| (<< first 24)
       (<< second 16)
       (<< third 8)
      fourth)))

;; An implmentation of the salsa 20/8 ARX stream cipher!
(defn- R [a b]
  (| (<< a b)
     (>>> a (- 32 b))))

(defn- set-R [array]
  (fn [idx x1 x2 n]
    (let [v (aget idx idx)
          xval (+ (aget array x1)
                  (aget array x2))]
      (xor= array idx (R xval n)))))

(defn salsa-20-8 [B]
  (let [B32 (make-array 16)
        x (make-array 16)
        xset (set-R x)]
    (forloop [(i 0) (< i 16) (inc i)]
      (->> (aget B i)
        flip-endian
        (aset B32 i)))
    (forloop [(i 0) (< i 16) (inc i)]
      (let [aligned-B32 (| (aget B32 i) 0)]
        (aset x i aligned-B32)))
    (forloop [(i 8) (> i 0) (- i 2)]
      (xset 4 0 12 7)
      (xset 8 4 0 9)
      (xset 12 8 4 13)
      (xset 0 12 8 18)
      (xset 9 5 1 7)
      (xset 13 9 5 9)
      (xset 1 13 9 13)
      (xset 5 1 13 18)
      (xset 14 10 6 7)
      (xset 2 14 10 9)
      (xset 6 2 14 13)
      (xset 10 6 2 18)
      (xset 3 15 11 7)
      (xset 7 3 15 9)
      (xset 11 7 3 13)
      (xset 15 11 7 18)
      (xset 1 0 3 7)
      (xset 2 1 0 9)
      (xset 3 2 1 13)
      (xset 0 3 2 18)
      (xset 6 5 4 7)
      (xset 7 6 5 9)
      (xset 4 7 6 13)
      (xset 5 4 7 18)
      (xset 11 10 9 7)
      (xset 8 11 10 9)
      (xset 9 8 11 13)
      (xset 10 9 8 18)
      (xset 12 15 14 7)
      (xset 13 12 15 9)
      (xset 14 13 12 13)
      (xset 15 14 13 18))
    (forloop [(i 0) (< i 16) (inc i)]
      (let [B32x (+ (aget B32 i) (aget x i))
            aligned-B32x (| B32x 0)]
        (aset B32 i aligned-B32x)))
    (forloop [(i 0) (< i 16) (inc i)]
      (->> (aget B32 i)
        flip-endian
        (aset B i)))
    B))
