(defproject spaceheater "0.1.0-SNAPSHOT"
  :description "A Litecoin mining library for cljs"
  :url "https://github.com/greenyouse/spaceheater"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.7.228"]
                 [org.clojure/google-closure-library "0.0-20151016-61277aea"]]

  :profiles {:dev {:dependencies [[com.cemerick/piggieback "0.2.1"]
                                  [figwheel "0.5.0-5"]
                                  [figwheel-sidecar "0.5.0-5"]]
                   :plugins [[lein-cljsbuild "1.1.2"]
                             [lein-figwheel "0.5.0-5"]]
                   ;; figwheel repl commands
                   ;; (use 'figwheel-sidecar.repl-api)
                   ;; (start-figwheel!)
                   ;; (cljs-repl)
                   ;; (start-autobuild :dev)
                   :repl-options
                   {:nrepl-middleware [cemerick.piggieback/wrap-cljs-repl]}}}

  :source-paths ["src"]

  :cljsbuild {:builds {:dev {:source-paths ["dev" "src"]
                             :figwheel true
                             :compiler {:output-to "resources/public/js/dev.js"
                                        :output-dir "resources/public/js/dev"
                                        :asset-path "js/dev"
                                        :optimizations :none
                                        :pretty-print true
                                        :main "spaceheater.core"
                                        :parallel-build true
                                        :source-map true
                                        :libs ["src/js/pbkdf2Sha256.js"]}}
                       :advanced {:source-paths ["src"]
                                  :compiler {:output-to "resources/public/js/spaceheater.js"
                                             :optimizations :advanced
                                             :parallel-build true
                                             :main "spaceheater.core"
                                             :source-map "resources/public/js/adv.js.map"
                                             :libs ["src/js/pbkdf2Sha256.js"]}}
                       :test {:source-paths ["src" "test"]
                              :notify-command ["phantomjs"
                                               "phantom/unit-test.js"
                                               "phantom/unit-test.html"]
                              :compiler {:output-to "resources/public/js/test.js"
                                         :output-dir "resources/public/js/test"
                                         :asset-path "src/js/test"
                                         :optimizations :whitespace
                                         :main "spaceheater.core"
                                         :pretty-print true
                                         :parallel-build true
                                         :libs ["src/js/pbkdf2Sha256.js"]}}}
              :test-commands {"unit-test" ["phantomjs"
                                           "phantom/unit-test.js"
                                           "phantom/unit-test.html"]}})
