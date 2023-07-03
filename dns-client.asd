(asdf:defsystem dns-client
  :version "1.0.0"
  :license "zlib"
  :author "Yukari Hafner <shinmera@tymoon.eu>"
  :maintainer "Yukari Hafner <shinmera@tymoon.eu>"
  :description "A client for the DNS protocol."
  :homepage "https://shinmera.github.io/dns-client/"
  :bug-tracker "https://github.com/shinmera/dns-client/issues"
  :source-control (:git "https://github.com/shinmera/dns-client.git")
  :serial T
  :components ((:file "package")
               (:file "toolkit")
               (:file "record-types")
               (:file "client")
               (:file "documentation"))
  :depends-on (:usocket
               :punycode
               :documentation-utils))
