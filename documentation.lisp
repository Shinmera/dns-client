#|
 This file is a part of dns-client
 (c) 2020 Shirakumo http://tymoon.eu (shinmera@tymoon.eu)
 Author: Nicolas Hafner <shinmera@tymoon.eu>
|#

(in-package #:org.shirakumo.dns-client)

;; toolkit.lisp
(docs:define-docs
  (type dns-condition
    "Base type for all DNS conditions.")
  
  (type dns-server-failure
    "Error signalled when a DNS server replies with a bad response code.

See DNS-CONDITION
See DNS-SERVER
See RESPONSE-CODE
See QUERY")

  (function dns-server
    "Returns the DNS server that returned the failure.

See DNS-SERVER-FAILURE")

  (function response-code
    "Returns the response code of the condition.

See DNS-SERVER-FAILURE
See RESPONSE-CODE-NAME")

  (type dns-servers-exhausted
    "Error signalled when all DNS servers fail to provide a response.

See DNS-CONDITION")

  (function response-code-name
    "Returns a name for the response code if one is known.")

  (function with-dns-error-handling
    "Wraps a handler around BODY that performs useful defaults.

In particular, it will cause CONTINUE to be invoked on all error
responses that are a failure on the server side, but still let the
error propagate for all failures that indicate a bad query.

See DNS-SERVER-FAILURE"))

;; record-types.lisp
(docs:define-docs
  (variable *record-type-table*
    "Table associating standardised names to DNS record type IDs.

This is a list where each entry should be a list of two elements, the
standardised name as a symbol, and the (unsigned-byte 16) ID.

You should not need to modify this. The table contains all
standardised records types.

See RECORD-TYPE-ID
See ID-RECORD-TYPE")
  
  (function record-type-id
    "Returns the record type ID for the given record name.

If ERROR is non-NIL, and the given record type does not exist, an
error is signalled. Otherwise, NIL is returned for inexistent record
types.

See *RECORD-TYPE-TABLE*")
  
  (function id-record-type
    "Returns the standardised record name for the given record type ID.

If the record type ID is not known, the ID itself is returned
instead.

See *RECORD-TYPE-TABLE*"))

;; client.lisp
(docs:define-docs
  (variable DNS-PORT
    "The port used for DNS queries.

Should be 53.")

  (variable RECV-BUFFER-LENGTH
    "The buffer size for received DNS packets.

Defaults to 65507, which should be more than enough for all DNS
queries. Note that while the standard DNS packet size used to (and
still is in some devices) limited to 512 bytes, this restriction no
longer applies generally.")
  
  (variable *cloudflare-servers*
    "List of IP addresses to CloudFlare's DNS servers.")

  (variable *dnswatch-servers*
    "List of IP addresses to DNSWatch's DNS servers.")

  (variable *google-servers*
    "List of IP addresses to Google's DNS servers.")

  (variable *opendns-servers*
    "List of IP addresses to OpenDNS' DNS servers.")

  (variable *quad9-servers*
    "List of IP addresses to Quad9's DNS servers.")

  (variable *dns-servers*
    "List of IP addresses to query for DNS records.

By default this is a combination of the localhost address and a bunch
of other publicly available DNS servers, in rough order of
trustworthiness and speed.

You may bind or modify this variable to suit your preferences.

See *CLOUDFLARE-SERVERS*
See *DNSWATCH-SERVERS*
See *GOOGLE-SERVERS*
See *OPENDNS-SERVERS*
See *QUAD9-SERVERS*
See QUERY")

  (function query
    "Perform a DNS query for the given hostname.

TYPE should be a DNS class name or class ID that identifies the type
of record you want to retrieve.

DNS-SERVERS should be a list of DNS servers to consult for your
query. Each server in the list is asked RETRIES number of times before
skipping ahead to the next one.

Returns a PLIST of the resulting query, if successful.

The result contains the following keys:

  :QUESTIONS    --- A list of QUERY structures.
  :ANSWERS      --- A list of RECORD structures.
  :AUTHORITIES  --- A list of RECORD structures.
  :ADDITIONAL   --- A list of RECORD structures.
  :ID           --- The ID identifying the query.
  :RECURSION-DESIRED   --- Whether recursion was asked for.
  :TRUNCATED-MESSAGE   --- Whether the message was truncated.
  :OPERATION    --- The operation that was carried out.
  :REPLY-P      --- Whether this is a reply.
  :RESPONSE-CODE       --- The response status code.
  :CHECKING-DISABLED   --- Whether checking was disabled.
  :AUTHENTICATED-DATA  --- Whether the data is authorative.
  :Z-RESERVED   --- Reserved flag.
  :RECURSION-AVAILABLE --- Whether the server allows recursion.
  :QUESTION-COUNT      --- How many QUESTION records there are.
  :ANSWER-COUNT        --- How many ANSWER records there are.
  :AUTHORITY-COUNT     --- How many AUTHORITY records there are.
  :ADDITIONAL-COUNT    --- How many ADDITIONAL records there are.

A query structure is a plist with the following keys:

  :NAME         --- The hostname that was queried.
  :TYPE         --- The record type that was queried.
  :CLASS        --- The record class that was queried.

A record structure is a plist with the following keys:

  :NAME         --- The hostname the result relates to.
  :TYPE         --- The record type.
  :CLASS        --- The record class.
  :TTL          --- The time this record remains valid for, in
                    minutes.
  :LENGTH       --- The length of the payload in octets.
  :DATA         --- A record type specific data payload.

The client will translate record types from their octet data into a
more easily digestible format for some record types:

  :A            --- An IPv4 address in string format.
  :AAAA         --- An IPv6 address in string format.
  :TXT :URI :CNAME :PTR
                --- A hostname.
  :MX           --- A plist with the following keys:
    :PRIORITY
    :NAME
  :SOA          --- A plist with the following keys:
    :MNAME
    :RNAME
    :SERIAL
    :REFRESH
    :RETRY
    :EXPIRE
    :MINIMUM

If a server is queried and has sent a response, but the response
contains a non-zero response code, a condition of type
DNS-SERVER-FAILURE is signalled. During this time, the CONTINUE
restart can be used to skip the server and attempt the next one,
or the ABORT restart can be used to simply return NIL from QUERY.

If no server succeeds, an error of type DNS-SERVERS-EXHAUSTED
is signalled.

See DNS-SERVER-FAILURE
See DNS-SERVERS-EXHAUSTED
See RESOLVE
See HOSTNAME")

  (function resolve
    "Resolves a hostname to its IP address.

This is a shorthand to fetch the A or AAAA records.

Returns three values, the first IP that was found (if any), a list of
all IPs that were found, and whether the query was successful. If the
last value is NIL, the first two values are NIL as well.

See QUERY")

  (function hostname
    "Perform a reverse DNS query.

Returns three values, the first hostname that was found (if any), a
list of all hostnames that were found, and whether the query was
successful. If the last value is NIL, the first two values are NIL as
well.

See QUERY"))

