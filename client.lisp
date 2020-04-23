#|
 This file is a part of dns-client
 (c) 2020 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.dns-client)

(defconstant DNS-PORT 53)
(defconstant RECV-BUFFER-LENGTH 65507)

(defvar *cloudflare-servers*
  '("1.1.1.1" "1.0.0.1"))
(defvar *dnswatch-servers*
  '("84.200.69.80" "84.200.70.40"))
(defvar *google-servers*
  '("8.8.8.8" "8.8.4.4"))
(defvar *opendns-servers*
  '("208.67.222.123" "208.67.220.123"))
(defvar *quad9-servers*
  '("9.9.9.9" "149.112.112.112"))
(defvar *dns-servers*
  (list* "127.0.0.1"
         (append *dnswatch-servers* *quad9-servers*
                 *cloudflare-servers* *opendns-servers*
                 *google-servers*)))

;;; TODO: Handle unicode.
(defun encode-host (name octets offset)
  (let ((start 0))
    (flet ((finish (end)
             (setf (aref octets (+ offset start)) (- end start))
             (loop for i from (1+ start) to end
                   do (setf (aref octets (+ offset i)) (char-code (char name (1- i)))))
             (setf start (1+ end))))
      (loop for i from 0 below (length name)
            do (when (char= #\. (char name i))
                 (finish i))
            finally (finish (length name)))
      (setf (aref octets (+ offset start)) 0)
      (+ offset start 1))))

(defun decode-host* (string)
  (loop with i = 0
        while (< i (length string))
        do (let ((jump (char-code (char string i))))
             (setf (char string i) #\.)
             (incf i (1+ jump))))
  string)

(defun decode-host (octets offset start)
  (loop with i = offset
        with pos = offset
        with jumped = NIL
        with stream = (make-string-output-stream)
        until (= 0 (aref octets i))
        ;; Handle label compression jump
        do (cond ((<= 192 (aref octets i))
                  (setf i (+ start
                             (- (+ (* 256 (aref octets i)) (aref octets (1+ i)))
                                #b1100000000000001)))
                  (setf jumped T)
                  (incf pos 1))
                 (T
                  (write-char (code-char (aref octets i)) stream)))
           (incf i)
           (unless jumped
             (incf pos))
        finally (return (values (decode-host* (get-output-stream-string stream)) (1+ pos)))))

(defun decode-header (octets offset)
  (with-decoding (octets offset pos)
    (values (list :id (int16)
                  :recursion-desired (int1)
                  :truncated-message (int1)
                  :authorative-answer (int1)
                  :operation (int4)
                  :reply-p (int1)
                  :response-code (int4)
                  :checking-disabled (int1)
                  :authenticated-data (int1)
                  :z-reserved (int1)
                  :recursion-available (int1)
                  :question-count (int16)
                  :answer-count (int16)
                  :authority-count (int16)
                  :additional-count (int16))
            pos)))

(defun encode-header (octets offset &key id recursion-desired truncated-message authorative-answer operation reply-p response-code checking-disabled authenticated-data z-reserved recursion-available question-count answer-count authority-count additional-count)
  (maybe-set (octets offset)
    (int16 id)
    (int1 recursion-desired)
    (int1 truncated-message)
    (int1 authorative-answer)
    (int4 operation)
    (int1 reply-p)
    (int4 response-code)
    (int1 checking-disabled)
    (int1 authenticated-data)
    (int1 z-reserved)
    (int1 recursion-available)
    (int16 question-count)
    (int16 answer-count)
    (int16 authority-count)
    (int16 additional-count)))

(defun encode-query (octets offset hostname &key type class)
  (let ((type (etypecase type
                ((or string symbol) (record-type-id type))
                ((unsigned-byte 16) type))))
    (setf offset (encode-host hostname octets offset))
    (maybe-set (octets offset)
      (int16 type)
      (int16 class))))

(defun decode-query (octets offset)
  (with-decoding (octets offset pos)
    (values (list :type (int16)
                  :class (int16))
            pos)))

(defun decode-data (octets offset)
  (with-decoding (octets offset pos)
    (values (list :type (id-record-type (int16))
                  :class (int16)
                  :ttl (int32)
                  :length (int16))
            pos)))

(defgeneric decode-record-payload (type octets start end))

(defmethod decode-record-payload (type octets start end)
  (subseq octets start end))

(defmethod decode-record-payload ((type (eql :A)) octets start end)
  (format NIL "~d.~d.~d.~d"
          (aref octets (+ 0 start))
          (aref octets (+ 1 start))
          (aref octets (+ 2 start))
          (aref octets (+ 3 start))))

(defmethod decode-record-payload ((type (eql :AAAA)) octets start end)
  (with-output-to-string (stream)
    (with-decoding (octets start)
      (loop for i from 0 below 8
            for group = (int16)
            do (when (/= 0 group)
                 (format stream "~4,'0x" group))
               (when (< i 7)
                 (format stream ":"))))))

(defmethod decode-record-payload ((type (eql :TXT)) octets start end)
  (decode-host octets start 0))

(defmethod decode-record-payload ((type (eql :URI)) octets start end)
  (decode-host octets start 0))

(defmethod decode-record-payload ((type (eql :CNAME)) octets start end)
  (decode-host octets start 0))

;; TODO: decode more.

(defmethod decode-record-payload ((type (eql :MX)) octets start end)
  (with-decoding (octets start pos)
    (list :priority (int16)
          :name (decode-host octets pos 0))))

(defmethod decode-record-payload ((type (eql :SOA)) octets start end)
  (multiple-value-bind (mname pos) (decode-host octets start 0)
    (multiple-value-bind (rname pos) (decode-host octets pos 0)
      (with-decoding (octets pos)
        (list :mname mname
              :rname rname
              :serial (int32)
              :refresh (int32)
              :retry (int32)
              :expire (int32)
              :minimum (int32))))))

(defun decode-record (octets offset)
  (multiple-value-bind (data pos) (decode-data octets offset)
    (setf (getf data :data) (decode-record-payload (getf data :type) octets pos (+ pos (getf data :length))))
    (values data (+ pos (getf data :length)))))

(defun decode-response (octets offset)
  (multiple-value-bind (header pos) (decode-header octets offset)
    (let ((record-offset pos))
      (flet ((decode (fun)
               (multiple-value-bind (name pos) (decode-host octets record-offset offset)
                 (multiple-value-bind (query pos) (funcall fun octets pos)
                   (setf record-offset pos)
                   (setf (getf query :name) name)
                   query))))
        (list :questions
              (loop repeat (getf header :question-count)
                    collect (decode #'decode-query))
              :answers
              (loop repeat (getf header :answer-count)
                    collect (decode #'decode-record))
              :authorities
              (loop repeat (getf header :authority-count)
                    collect (decode #'decode-record))
              :additional
              (loop repeat (getf header :additional-count)
                    collect (decode #'decode-record)))))))

(defun try-server (server send send-length recv recv-length &key (retries 3))
  (handler-case
      (let ((socket (usocket:socket-connect server DNS-PORT
                                            :protocol :datagram
                                            :element-type '(unsigned-byte 8)
                                            :timeout 1)))
        (unwind-protect
             (loop repeat retries
                   do (usocket:socket-send socket send send-length)
                      (let ((received (nth-value 1 (usocket:socket-receive socket recv recv-length))))
                        (when (and received (< 0 received))
                          (return received))))
          (usocket:socket-close socket)))
    (usocket:socket-error (e)
      (values NIL e))))

(defun build-query (hostname type)
  (let* ((send (make-array 512 :element-type '(unsigned-byte 8) :initial-element 0))
         (pos (encode-header send 0 :id 42 :recursion-desired T :question-count 1))
         (pos (encode-query send pos hostname :type type :class 1)))
    (values send pos)))

(defun query (hostname &key (type T) (dns-servers *dns-servers*) (retries 3))
  (let ((recv (make-array RECV-BUFFER-LENGTH :element-type '(unsigned-byte 8) :initial-element 0)))
    (multiple-value-bind (send send-length) (build-query hostname type)
      (loop for server in dns-servers
            for recv-length = (try-server server send send-length recv RECV-BUFFER-LENGTH :retries retries)
            do (when recv-length
                 (return (decode-response recv 0)))
            finally (error "Failed to get a response from any server.")))))

(defun query-data (hostname &rest args)
  (loop for record in (getf (apply #'query hostname args) :answers)
        collect (getf record :data)))

(defun resolve (hostname &rest args)
  (let ((list (append (apply #'query-data hostname :type :A args)
                      (apply #'query-data hostname :type :AAAA args))))
    (values (first list) list)))
