(ns r-incantations.core
  (:require [incanter.core]
            [incanter.stats]
            [incanter.charts]
            [clojure.edn :as edn]
            [clojure.math.numeric-tower :as math]
            [clojure.java.shell :refer [sh]]
            [net.n01se.clojure-jna :as jna]
            [clojure.string :as str]))

(defn sd []
  ;; sd(rbind(c(1,2,3), c(4,5,6)))
  (incanter.stats/sd (apply concat [[1 2 3] [4 5 6]])))

(defn matrix-mean []
  ;; R: mean(matrix(c(1,2,3,4,5,6,7,8,9,10,11,12), ncol=4))
  ;; pandas: pd.DataFrame([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]], index = ["i1", "i2", "i3"], columns = list('ABCD'))
  (incanter.stats/mean (apply concat (incanter.core/matrix [1 2 3 4 5 6 7 8 9 10 11 12] 4))))

(defn cols-with-multiple-of-n [m n rowidx]
  "(cols-with-multiples-of-n
    (incanter.core/matrix [1 2 3 4 5 6 7 8 9 10 11 12] 4) 3 2)"
  (incanter.core/trans
   (filter #(zero? (mod (nth % rowidx) n))
           (incanter.core/trans m))))

(defn plot-summed-vectors-r []
  (let [r "x1 <- rnorm(100)
           x2 <- rnorm(100)
           x3 <- rnorm(100)
           t <- data.frame (a = x1, b = x1 + x2, c = x1 + x2 + x3)
           #t <- data.frame (a = x1, b = x2, c = x3)
           png(file = \"/tmp/rplot.png\", bg = \"transparent\")
           plot(t)
           dev.off()"]
    (sh "R" "--no-save" "-q" :in r)))

(defn plot-summed-vectors-pandas
  "Doesn't work. On my system, Canopy's wx dependency is the issue."
  []
  (let [p "
import numpy as np
import scipy as sp
import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd
tmp = pd.scatter_matrix(pd.DataFrame([x1, x1 + x2, x1 + x2 + x3], ['a', 'b', 'c'], range(100)).T
fig = tmp.get_figure()
fig.save_figure('/tmp/pplot.png')"]
    (spit "/tmp/a.py" p)
    ))

(defn read-strings1 [coll]
  (map (fn read-strings- [t]
         (try
           (let [s (edn/read-string t)]
             (if (symbol? s)
               (str s)
               s))
           (catch Exception e t)))
       coll))

(defn read-alienvault-reputation-data []
  (-> "book-data/book/ch03/data/reputation.data"
      (incanter.io/read-dataset :delim \#)
      (incanter.core/col-names
       ["IP" "Reliability" "Risk" "Type" "Country" "Locale" "Coords" "x"])))

(defn ch03
  ([] (ch03 (read-alienvault-reputation-data)))
  ([av]
     (let [summary (incanter.stats/summary av)
           rr-summary (incanter.stats/summary
                       (incanter.core/sel av :cols ["Risk" "Reliability"]))]
       {:summary summary
        :rr-summary rr-summary})))

;;----------------------------
;; Data-Driven Security ch04
;;----------------------------
(defn parse-int
  "Nice idea from
   http://stackoverflow.com/questions/5621279/in-clojure-how-can-i-convert-a-string-to-a-number"
  [s]
  (Integer. (re-find #"\d+" s)))

(defn ipv4->int
  "Convert a 4-octet string representing an IP address into an integer."
  [addr]
  (let [bytes (str/split addr #"\.")
        bytes (map parse-int bytes)]
    (reduce +
            (map-indexed
             (fn ip->int- [idx b]
               (bit-shift-left b (* 8 (- 3 idx ))))
             bytes))))

(defn int->ipv4
  "Convert an integer representing an IP address into the usual 4-octet string."
  [addr]
  (str/join \. (map (fn nf [shift]
                      (let [mask (bit-shift-left 0xff shift)]
                        (bit-shift-right (bit-and addr mask)
                                         shift)))
                 (reverse (range 0 32 8)))))

(defn ipv4-in-cidr? [addr cidr]
  (let [[cidr-addr suffix] (str/split cidr #"/")
        mask (- 32 (parse-int suffix))
        a (bit-shift-right (ipv4->int addr) mask)
        b (bit-shift-right (ipv4->int cidr-addr) mask)]
    (= a b)))

(defn get-iana-ipv4-allocations []
  (-> "book-data/book/ch04/data/ipv4-address-space.csv"
      ;; eat the headers, but don't use them because one column has a SPACE in the name and clojure.core/keyword allows this
      (incanter.io/read-dataset :skip 1)
      (incanter.core/col-names
       [:Prefix :Designation :Date :Whois :Status :Note])))

(defn ch04 []
  (let [iana (get-iana-ipv4-allocations)
        iana (incanter.core/replace-column
              :Prefix
              (map (fn [x] (str/replace x #"(^00|^0|/8$)" ""))
                   (incanter.core/$ :Prefix iana))
              iana)
        ;; We don't technically need a derived column, here; we just
        ;; need a seq of all the IP prefixes in av. But this is one way to do it.
        av (incanter.core/add-derived-column
            :IP.Prefix
            ["IP"]
            (fn [ip] (first (str/split ip #"\.")))
            (read-alienvault-reputation-data))
        av (incanter.core/add-column
            :Designation
            (map (fn [x] (incanter.core/$ :Designation
                                          (incanter.core/query-dataset iana
                                                                       {:Prefix x})))
                 (incanter.core/$ :IP.Prefix av))
            av)]
    {:iana iana
     :av av}))

(defn r-like-table [coll]
  (let [n (incanter.core/nrow coll)
        p (incanter.core/ncol coll)]
    (loop [tab {} i (int 0)]
      (if (= i n)
        tab
        (recur (let [row (if (> p 1)
                           (incanter.core/to-list (nth coll i))
                           (nth coll i))
                     cnt (get tab row)]
                 (if (nil? cnt)
                   (assoc tab row 1)
                   (assoc tab row (inc cnt))))
               (inc i))))))

(defn get-zeroaccess-data []
  (-> "book-data/book/ch05/data/zeroaccess.csv"
      ;; eat the headers, but don't use them because one column has a SPACE in the name and clojure.core/keyword allows this
      (incanter.io/read-dataset :header true)))

(defn get-state-population-data []
  (let [spd (incanter.io/read-dataset
             "book-data/book/ch05/data/state-internets.csv"
             :header true)]
    ;; lower-case the state names
    (incanter.core/replace-column
     :state
     (map #(str/lower-case %)
          (incanter.core/$ :state spd))
     spd)))

(defn ch05-1 []
  (let [za (r-incantations.core/get-zeroaccess-data)
        lat (incanter.core/$ :lat za)
        long (incanter.core/$ :long za)]
    (-> (incanter.charts/scatter-plot long lat)
        (incanter.charts/set-point-size 1)
        (incanter.charts/set-alpha 1/40)
        incanter.core/view)))

(defn get-world []
  (let [filepath "world.csv"]
    (-> filepath
        ;; eat the headers, but don't use them because one column has a SPACE in the name and clojure.core/keyword allows this
        (incanter.io/read-dataset :header true))))

(defn world-map []
  (let [world (get-world)
        lon (incanter.core/$ :long world)
        lat (incanter.core/$ :lat world)]
    (-> (incanter.charts/scatter-plot lon lat)
        (incanter.charts/set-point-size 1)
        (incanter.charts/set-stroke-color java.awt.Color/gray))))

(defn ch05-2
  "Initially intended to do Listing 5-8 on p.114, but latlong2map()
   does polygon point inclusion testing (with R's over()), and I don't
   know (yet) of an implementation of that in Clojure that I have
   available."
  []
  (let [za (get-zeroaccess-data)
        users (get-state-population-data)]
    ;; Oh. Now we need to test polygon inclusion, such as is described
    ;; and represented here in C++:
    ;; http://geomalgorithms.com/a03-_inclusion.html
    ;; Guess we'll do that another day.
    [za users]))

(defn ch05-3
  "Based on Listing 5-16 through 5-18"
  [intercept?]
  (let [relation-fn #(* 2 %)
        input (incanter.stats/sample-normal 20000 :mean 10)
        output (map #(incanter.stats/sample-normal 1 :mean (relation-fn %)) input)
        _demo-dataset (incanter.core/to-dataset (incanter.core/bind-columns input output))
        model (incanter.stats/linear-model output input :intercept intercept?)
        _cool! (incanter.stats/predict model 42)]
    {:model model}
    (comment
      :graph (-> (incanter.charts/scatter-plot input output)
                 (incanter.charts/add-lines input (:fitted model)))
      :residuals-quantiles (incanter.stats/quantile (:residuals model))
      :intercept (-> model :coefs first)
      :intercept2 (incanter.stats/predict model 0)
      :confint-intercept (-> model :coefs-ci first)
      :confint-input-coef (-> model :coefs-ci last)
      :adj-r-square model)))

(comment
  ;; hist(rnorm(100))
  (incanter.core/view (incanter.charts/histogram (incanter.stats/sample-normal 100)))

  (incanter.stats/mean (apply concat (incanter.core/matrix [1 2 3 4 5 6 7 8 9] 3)))

  
  ;; slide 53 of http://incanter.org/docs/data-sorcery-new.pdf
  (->> (incanter.datasets/get-dataset :iris)
       (incanter.core/$where {:Petal.Length {:lte 2.0}
                              :Petal.Width {:lt 0.75}})
       (incanter.charts/scatter-plot :Petal.Width :Petal.Length :data)
       incanter.core/view)

  ;; slide 54 of http://incanter.org/docs/data-sorcery-new.pdf
  (incanter.core/with-data (incanter.datasets/get-dataset :iris)
    (doto (incanter.charts/scatter-plot :Petal.Width :Petal.Length
                                        :data (incanter.core/$where {:Petal.Length {:lte 2.0}
                                                                     :Petal.Width {:lt 0.75}}))
      (incanter.charts/add-points :Petal.Width :Petal.Length
                                  :data (incanter.core/$where {:Petal.Length {:gt 2.0}
                                                               :Petal.Width {:gte 0.75}}))
      incanter.core/view))

  ;; slide 55 of http://incanter.org/docs/data-sorcery-new.pdf
  (incanter.core/with-data (incanter.datasets/get-dataset :iris)
    (let [lm (incanter.stats/linear-model
              (incanter.core/$ :Petal.Length) (incanter.core/$ :Petal.Width))]
      (doto (incanter.charts/scatter-plot :Petal.Width :Petal.Length
                                          :data (incanter.core/$where {:Petal.Length {:lte 2.0}
                                                                       :Petal.Width {:lt 0.75}}))
        (incanter.charts/add-points :Petal.Width :Petal.Length
                                    :data (incanter.core/$where {:Petal.Length {:gt 2.0}
                                                                 :Petal.Width {:gte 0.75}}))
        (incanter.charts/add-lines :Petal.Width (:fitted lm))
        incanter.core/view)))


  (->> (incanter.datasets/get-dataset :iris)
           (incanter.core/$rollup :mean :Sepal.Length :Species)
           (incanter.charts/bar-chart :Species :Sepal.Length :data)
           incanter.core/view)

  (doto (incanter.charts/function-plot incanter.core/sin -10 10)
    (incanter.charts/add-image 0 0 (incanter.latex/latex "\\frac{(a+b)^2} {(a-b)^2}"))
    incanter.core/view)

  ;; slide 58 of http://incanter.org/docs/data-sorcery-new.pdf
  (incanter.core/with-data
    (incanter.core/$rollup :mean :count [:hair :eye]
                           (incanter.datasets/get-dataset :hair-eye-color))
    (incanter.core/view incanter.core/$data))

  ;; slide 66 of http://incanter.org/docs/data-sorcery-new.pdf
  (-> (incanter.charts/function-plot cubic -10 10)
      (incanter.charts/add-function (incanter.optimize/derivative cubic) -10 10)
      incanter.core/view)

  ;; slide 69 of http://incanter.org/docs/data-sorcery-new.pdf
  (-> (incanter.charts/histogram (incanter.stats/sample-gamma 1000)
                                 :density true
                                 :nbins 30)
      (incanter.charts/add-function incanter.stats/pdf-gamma 0 8)
      (incanter.core/view))

  ;; fails to map alaska nicely
  (let [ak (incanter.core/$where {:region "USA" :subregion "Alaska" :group 25} world)
        coords (incanter.core/sel ak :cols [:long :lat])
        coords (incanter.core/to-matrix coords)
        p (incanter.charts/xy-plot (map first coords) (map second coords))
        p (incanter.charts/add-polygon p coords)]
    (incanter.core/view p))
  
  
  )
