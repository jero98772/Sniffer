(ns clojuresnif.web
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.resource :refer [wrap-resource]]
            ;[clojuresnif.core :refer [timed-kmp timed-rabin-karp timed-boyer-moore]]
))

(defroutes app-routes
  (GET "/" [] {:status 200
               :headers {"Content-Type" "text/html"}
               :body (slurp (clojure.java.io/resource "public/index.html"))})
)  

(def app
  (-> app-routes
      (wrap-resource "public")  ;; Serve static files
      wrap-params))