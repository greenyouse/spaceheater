(ns spaceheater.scrypt
  "An implementation of the scrypt algorithm based on the spec:
  https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04,
  https://github.com/bitwiseshiftleft/sjcl, and
  http://www.tarsnap.com/scrypt/scrypt.pdf"
  (:require [goog.crypt :as gc]
            [goog.crypt.pbkdf2Sha256 :as p])
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

(defn- blockxor [S Si D Di len]
  (let [len (/ len 4)
        Si (/ Si 4)
        Di (/ Di 4)]
    (forloop [(i 0) (< i len) (inc i)]
      (let [D-idx (+ Di i)
            S-idx (+ Si i)]
        (xor= D D-idx (| S-idx 0))))))

(defn- blockcopy [S Si D Di len]
  (let [len (/ len 4)
        Si (/ Si 4)
        Di (/ Di 4)]
    (forloop [(i 0) (< i len) (inc i)]
      (let [D-idx (+ Di i)
            S-idx (+ Si i)]
        (aset D D-idx (| S-idx 0))))))

(defn- blockmix-salsa8
  "BY -- The desired key length parameter
  Bi -- zero
  Yi -- r * 128
  r -- parallelization number"
  [BY Bi Yi r]
  (let [X (make-array 16)]
    (blockcopy BY (* (* 2 (- r 1)) 64) X 0 64)
    (forloop [(i 0) (< i 2) (inc i)]
      (blockxor BY (* i 64) X 0 64)
      (salsa-20-8 X)
      (blockcopy X 0 BY (+ Yi (* i 64)) 64))
    (forloop [(i 0) (< i r) (inc i)]
      (blockcopy BY (+ Yi (* (* i 2) 64)) BY (+ Bi (* i 64)) 64)
      (blockcopy BY (+ Yi (* (+ (* i 2) 1) 64)) BY (+ Bi (* (+ i r) 64)) 64))))

(defn- integerify [B Bi r]
  (let [Bi (+ Bi (* (- (* 2 r) 1) 64))]
    (flip-endian (aget B (/ Bi 4)))))

(defn- smix
  "A hard sequential memory function to mix blocks with
  B -- pbkdf2 output
  r -- The CPU latency parameter
  N --  The CPU/memory cost parameter"
  [B Bi r N V XY]
  (let [Xi 0
        Yi (* 128 r)]
    (blockcopy B Bi XY Xi Yi)
    (forloop [(i 0) (< i N) (inc i)]
      (blockcopy XY Xi V (* i Yi) Yi)
      (blockmix-salsa8 XY Xi Yi r))
    (forloop [(i 0) (< i N) (inc i)]
      (let [j (b& (integerify XY Xi r) (dec N))]
        (blockxor V (* j Yi) XY Xi Yi)
        (blockmix-salsa8 XY Xi Yi r)))
    (blockcopy XY Xi B Bi Yi)))

(defn scrypt
  "Derives the key from a password using Scrypt (memory intensive, hard to
  do parallel processing). LiteCoin dictates N=1024, r=1, p=1,
  dkLen=256 bits or 32 bytes

  passwd -- Byte array of the password
  salt -- Byte array of the salt
  N -- CPU/memeory cost parameter
  r -- CPU memory latency parameter
  p -- CPU parallelization parameter
  dkLen -- Intended output length of derived key, in octets"
  [passwd salt N r p dkLen]
  (assert (<= (* r p) (js/Math.pow 2 30))
    (str "The parameters r and p must satisfy r * p < 2^30;
     current value: " (* r p)))
  (assert (or (> N 2) (= 0 (b& N (dec N))))
    "Ther parameter N must be a power of 2.")
  (let [max (dec (js/Math.pow 2 32))]
    (assert (<= N (/ max (/ 128 r)))
      "N too big")
    (assert (<= r (/ max (/ 128 p)))
      "r too big"))
  (let [B (p/deriveKeySha256
            (gc/stringToByteArray passwd)
            (gc/stringToByteArray salt)
            1 (* p 128 r 8))
        V (make-array 16)
        XY (make-array 16)]
    (forloop [(i 0) (< i p) (inc i)]
      (smix B (* i 128 r) r N V XY))
    (p/deriveKeySha256
      (gc/stringToByteArray passwd)
      B 1 (* dkLen 8))))
