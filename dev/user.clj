(ns user
  (:require [incanter.core]
            [incanter.stats]
            [incanter.charts]
            [incanter.datasets]
            [incanter.pdf]
            [incanter.optimize]
            [clojure.edn :as edn]
            [cemerick.pomegranate :as pomegranate]
            [clojure.data.csv :as csv]
            [clojure.string :as str]
            [net.n01se.clojure-jna :as jna]
            [clojure.math.numeric-tower :as math]))
