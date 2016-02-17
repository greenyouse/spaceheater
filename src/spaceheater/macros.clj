(ns spaceheater.macros)

;; from https://github.com/swannodette/chambered/blob/master/src/chambered/macros.clj
(defmacro forloop
  "An imperative style loop that can mutate a JavaScript array"
  [[init test step] & body]
  `(loop [~@init]
     (when ~test
       ~@body
       (recur ~step))))
