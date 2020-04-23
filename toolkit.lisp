#|
 This file is a part of dns-client
 (c) 2020 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.dns-client)

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
