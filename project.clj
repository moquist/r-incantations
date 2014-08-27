(defproject r-incantations "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["dev"]
  :profiles {:dev
             ;; There's really no "prod" for this project, but separate out something like pomegranate anyhow.
             {:dependencies [[com.cemerick/pomegranate "0.3.0"]]}}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [incanter "1.5.5"]
                 [org.clojure/data.csv "0.1.2"]
                 [net.n01se/clojure-jna "1.0.0"]
                 [org.clojure/math.numeric-tower "0.0.4"]])
