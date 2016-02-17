(ns spaceheater.scrypt-test
  (:require [cljs.test :as test :refer [test-var]
             :refer-macros [are is deftest]]
            [spaceheater.scrypt :as s]))

;; FIXME: get these running properly
;; salsa 20/8 test vectors
;; https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04#section-8
(comment
  (deftest salsa-20-8-test []
    (are [expected in]
        (= expected (s/salsa-20-8 in))

      #js [164, 31, 133, 156, 102, 8, 204, 153, 59, 129, 202, 203, 2, 12, 239, 5]
      #js [126, 135, 154, 33, 79, 62, 201, 134, 124, 169, 64, 230, 65, 113, 143]

      #js [4, 75, 33, 129, 162, 253, 51, 125, 253, 123, 28, 99, 150, 104, 47, 41]
      #js [47714, 238, 85, 91, 140, 97, 193, 181, 13, 248, 70, 17, 109, 205, 59, 29]

      #js [180, 57, 49, 104, 227, 201, 230, 188, 254, 107, 197, 183, 160, 109, 150, 186]
      #js [238, 36, 243, 25, 223, 155, 61, 133, 20, 18, 30, 75, 90, 197, 170, 50]

      #js [228, 36, 204, 16, 44, 145, 116, 92, 36, 173, 103, 61, 199, 97, 143, 129]
      #js [118, 2, 29, 41, 9, 199, 72, 41, 237, 235, 198, 141, 184, 194, 94])))
