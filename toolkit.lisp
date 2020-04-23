#|
 This file is a part of dns-client
 (c) 2020 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.dns-client)

(define-condition dns-condition ()
  ())

(define-condition dns-server-failure (error dns-condition)
  ((dns-server :initarg :dns-server :accessor dns-server)
   (response-code :initarg :response-code :accessor response-code))
  (:report (lambda (c s) (format s "DNS server ~%  ~a~%responded with failure code ~d~@[~%  ~a~]"
                                 (dns-server c) (response-code c) (response-code-name (response-code c))))))

(define-condition dns-servers-exhausted (error dns-condition)
  ()
  (:report (lambda (c s) (format s "All DNS servers failed to provide an answer for the query."))))

(defun response-code-name (code)
  (case code
    (0 :success)
    (1 :format-error)
    (2 :server-failure)
    (3 :no-such-domain)
    (4 :not-implemented)
    (5 :query-refused)
    (6 :name-should-not-exist)
    (7 :set-should-not-exist)
    (8 :set-does-not-exist)
    (9 :not-authorized)
    (10 :not-in-zone)
    (11 :type-not-implemented)
    (16 :bad-version)
    (17 :key-not-recognised)
    (18 :bad-time)
    (19 :bad-mode)
    (20 :duplicate-key)
    (21 :bad-algorithm)
    (22 :bad-truncation)
    (23 :bad-cookie)))

(defmacro with-dns-error-handling (&body body)
  `(handler-bind ((dns-server-failure
                    (lambda (e)
                      (unless (find (response-code e) '(1 3 6 7 8))
                        (continue e)))))
     ,@body))

;;; Note: we assume that we never cross byte boundaries when accessing bits.
(defmacro with-decoding ((octets start &optional (pos (gensym "POS"))) &body body)
  `(let ((,pos ,start))
     (flet ((int1 ()
              (prog1 (logbitp (* 8 (rem ,pos 1)) (aref ,octets (floor ,pos)))
                (incf ,pos 1/8)))
            (int4 ()
              (prog1 (ldb (byte 4 (* 8 (rem ,pos 1))) (aref ,octets (floor ,pos)))
                (incf ,pos 4/8)))
            (int8 ()
              (prog1 (aref ,octets (floor ,pos))
                (incf ,pos 1)))
            (int16 () ;; big-endian
              (prog1 (+ (ash (aref ,octets (+ 0 (floor ,pos))) 8)
                        (ash (aref ,octets (+ 1 (floor ,pos))) 0))
                (incf ,pos 2)))
            (int32 ()
              (prog1 (+ (ash (aref ,octets (+ 0 (floor ,pos))) 24)
                        (ash (aref ,octets (+ 1 (floor ,pos))) 16)
                        (ash (aref ,octets (+ 2 (floor ,pos))) 8)
                        (ash (aref ,octets (+ 3 (floor ,pos))) 0))
                (incf ,pos 4))))
       (declare (ignorable #'int1 #'int4 #'int8 #'int16 #'int32))
       ,@body)))

(defmacro with-encoding ((octets start &optional (pos (gensym "POS"))) &body body)
  `(let ((,pos ,start))
     (flet ((int1 (value)
              (let ((octet (aref ,octets (floor ,pos))))
                (setf (ldb (byte 1 (* 8 (rem ,pos 1))) octet)
                      (ecase value
                        ((0 1) value)
                        ((T) 1)
                        ((NIL) 0)))
                (setf (aref ,octets (floor ,pos)) octet)
                (incf ,pos 1/8)))
            (int4 (value)
              (let ((octet (aref ,octets (floor ,pos))))
                (setf (ldb (byte 4 (* 8 (rem ,pos 1))) octet) value)
                (setf (aref ,octets (floor ,pos)) octet)
                (incf ,pos 4/8)))
            (int8 (value)
              (setf (aref ,octets (floor ,pos)) value)
              (incf ,pos 1))
            (int16 (value) ;; big-endian
              (setf (aref ,octets (+ 0 ,pos)) (ldb (byte 8 8) value))
              (setf (aref ,octets (+ 1 ,pos)) (ldb (byte 8 0) value))
              (incf ,pos 2))
            (int32 (value) ;; big-endian
              (setf (aref ,octets (+ 0 ,pos)) (ldb (byte 8 24) value))
              (setf (aref ,octets (+ 1 ,pos)) (ldb (byte 8 16) value))
              (setf (aref ,octets (+ 2 ,pos)) (ldb (byte 8 8) value))
              (setf (aref ,octets (+ 3 ,pos)) (ldb (byte 8 0) value))
              (incf ,pos 4)))
       (declare (ignorable #'int1 #'int4 #'int8 #'int16 #'int32))
       ,@body)))

(defmacro maybe-set ((octets offset) &body calls)
  `(with-encoding (,octets ,offset pos)
     ,@(loop for (func value) in calls
             collect `(if ,value
                          (,func ,value)
                          (incf pos ,(ecase func
                                       (int1 1/8)
                                       (int4 4/8)
                                       (int8 1)
                                       (int16 2)
                                       (int32 4)))))
     pos))

(defun split (on string)
  (let ((parts ())
        (buffer (make-string-output-stream)))
    (flet ((finish ()
             (let ((buffer (get-output-stream-string buffer)))
               (push buffer parts))))
      (loop for char across string
            do (if (char= on char)
                   (finish)
                   (write-char char buffer))
            finally (finish)))
    (nreverse parts)))
