(ns test-runner
  (:require [cljs.test :refer-macros [run-tests]]
            [spaceheater.scrypt]))

(enable-console-print!)

(defn runner []
  (if (cljs.test/successful?
        (run-tests
          'spaceheater.scrypt))
    0
    1))
