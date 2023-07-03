(defpackage #:org.shirakumo.dns-client
  (:use #:cl)
  ;; client.lisp
  (:export
   #:DNS-PORT
   #:RECV-BUFFER-LENGTH
   #:*cloudflare-servers*
   #:*dnswatch-servers*
   #:*google-servers*
   #:*opendns-servers*
   #:*quad9-servers*
   #:*dns-servers*
   #:query
   #:query-data
   #:resolve
   #:hostname)
  ;; record-types.lisp
  (:export
   #:*record-type-table*
   #:record-type-id
   #:id-record-type)
  ;; toolkit.lisp
  (:export
   #:dns-condition
   #:dns-server-failure
   #:dns-server
   #:response-code
   #:dns-servers-exhausted
   #:response-code-name
   #:with-dns-error-handling))
