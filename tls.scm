;; (declare
;;   (module (tls))
;;   (import (chicken foreign))
;;   (disable-interrupts)
;;   (fixnum-arithmetic)
;;   (export
;;    tls-version

;;    tls-init!
;;    tls-config-error
;;    tls-error
;;    tls-config-new
;;    tls-config-free
;;    tls-default-ca-cert-file

;;    tls-config-add-keypair-file!
;;    tls-config-add-keypair-mem!
;;    tls-config-add-keypair-ocsp-file!
;;    tls-config-add-keypair-ocsp-mem!
;;    tls-config-set-alpn!
;;    tls-config-set-ca-file!
;;    tls-config-set-ca-path!
;;    tls-config-set-ca-mem!
;;    tls-config-set-cert-file!
;;    tls-config-set-cert-mem!
;;    tls-config-set-ciphers!
;;    tls-config-set-crl-file!
;;    tls-config-set-crl-mem!
;;    tls-config-set-dheparams!
;;    tls-config-set-ecdhecurve!
;;    tls-config-set-ecdhecurves!
;;    tls-config-set-key-file!
;;    tls-config-set-key-mem!
;;    tls-config-set-keypair-file!
;;    tls-config-set-keypair-mem!
;;    tls-config-set-keypair-ocsp-file!
;;    tls-config-set-keypair-ocsp-mem!
;;    tls-config-set-ocsp-staple-mem!
;;    tls-config-set-ocsp-staple-file!
;;    tls-config-set-protocols!
;;    tls-config-set-session-fd!
;;    tls-config-set-verify-depth!
;;    tls-config-prefer-ciphers-client!
;;    tls-config-prefer-ciphers-server!
;;    tls-config-insecure-noverifycert!
;;    tls-config-insecure-noverifyname!
;;    tls-config-insecure-noverifytime!
;;    tls-config-verify!
;;    tls-config-ocsp-require-stapling!
;;    tls-config-verify-client!
;;    tls-config-verify-client-optional!
;;    tls-config-clear-keys!
;;    tls-config-parse-protocols
;;    tls-config-set-session-id!
;;    tls-config-set-session-lifetime!
;;    tls-config-add-ticket-key!
;;    tls-client
;;    tls-server
;;    tls-configure!
;;    tls-reset!
;;    tls-free!
;;    tls-accept-fds
;;    tls-accept-socket
;;    tls-accept-cbs
;;    tls-connect
;;    tls-connect-fds
;;    tls-connect-servername
;;    tls-connect-socket
;;    tls-connect-cbs
;;    tls-handshake
;;    tls-read
;;    tls-write
;;    tls-close
;;    tls-peer-cert-provided?
;;    tls-peer-cert-contains-name?
;;    tls-peer-cert-hash
;;    tls-peer-cert-issuer
;;    tls-peer-cert-subject
;;    tls-peer-cert-notbefore
;;    tls-peer-cert-notafter
;;    tls-peer-cert-chain-pem
;;    tls-conn-alpn-selected
;;    tls-conn-cipher
;;    tls-conn-servername
;;    tls-conn-session-resumed
;;    tls-conn-version
;;    tls-load-file
;;    tls-unload-file!
;;    tls-ocsp-process-response
;;    tls-peer-ocsp-cert-status
;;    tls-peer-ocsp-crl-reason
;;    tls-peer-ocsp-next-update
;;    tls-peer-ocsp-response-status
;;    tls-peer-ocsp-result
;;    tls-peer-ocsp-revocation-time
;;    tls-peer-ocsp-this-update
;;    tls-peer-ocsp-url
;;    ))


;;; Scheme bindings to LibreSSL's libTLS API.
;;;
;;; TODO:
;;; - Fix time_t handling, currently uses integer64
;;; -
;;;


(import (chicken foreign))

(foreign-declare "#include <tls.h>")

;; #define TLS_API	20180210
(define (tls-version)
  (foreign-value "TLS_API" int))

;; #define TLS_PROTOCOL_TLSv1_0	(1 << 1)
;; #define TLS_PROTOCOL_TLSv1_1	(1 << 2)
;; #define TLS_PROTOCOL_TLSv1_2	(1 << 3)
;; #define TLS_PROTOCOL_TLSv1 \
;; 	(TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2)

;; #define TLS_PROTOCOLS_ALL TLS_PROTOCOL_TLSv1
;; #define TLS_PROTOCOLS_DEFAULT TLS_PROTOCOL_TLSv1_2

;; #define TLS_WANT_POLLIN		-2
;; #define TLS_WANT_POLLOUT	-3

;; /* RFC 6960 Section 2.3 */
;; #define TLS_OCSP_RESPONSE_SUCCESSFUL		0
;; #define TLS_OCSP_RESPONSE_MALFORMED		1
;; #define TLS_OCSP_RESPONSE_INTERNALERROR		2
;; #define TLS_OCSP_RESPONSE_TRYLATER		3
;; #define TLS_OCSP_RESPONSE_SIGREQUIRED		4
;; #define TLS_OCSP_RESPONSE_UNAUTHORIZED		5

;; /* RFC 6960 Section 2.2 */
;; #define TLS_OCSP_CERT_GOOD			0
;; #define TLS_OCSP_CERT_REVOKED			1
;; #define TLS_OCSP_CERT_UNKNOWN			2

;; /* RFC 5280 Section 5.3.1 */
;; #define TLS_CRL_REASON_UNSPECIFIED		0
;; #define TLS_CRL_REASON_KEY_COMPROMISE		1
;; #define TLS_CRL_REASON_CA_COMPROMISE		2
;; #define TLS_CRL_REASON_AFFILIATION_CHANGED	3
;; #define TLS_CRL_REASON_SUPERSEDED		4
;; #define TLS_CRL_REASON_CESSATION_OF_OPERATION	5
;; #define TLS_CRL_REASON_CERTIFICATE_HOLD		6
;; #define TLS_CRL_REASON_REMOVE_FROM_CRL		8
;; #define TLS_CRL_REASON_PRIVILEGE_WITHDRAWN	9
;; #define TLS_CRL_REASON_AA_COMPROMISE		10

;; #define TLS_MAX_SESSION_ID_LENGTH		32
;; #define TLS_TICKET_KEY_SIZE			48

;; struct tls;
;; struct tls_config;

;; typedef ssize_t (*tls_read_cb)(struct tls *_ctx, void *_buf, size_t _buflen,
;;     void *_cb_arg);
;; typedef ssize_t (*tls_write_cb)(struct tls *_ctx, const void *_buf,
;;     size_t _buflen, void *_cb_arg);

;; int tls_init(void);
(define (tls-init!)
  ((foreign-lambda int "tls_init")))

;; const char *tls_config_error(struct tls_config *_config);
(define (tls-config-error cfg)
  ((foreign-lambda (const c-string) "tls_config_error" (c-pointer "struct tls_config")) cfg))
;; const char *tls_error(struct tls *_ctx);
(define (tls-error ctx)
  ((foreign-lambda (const c-string) "tls_error" (c-pointer "struct tls")) ctx))

;; struct tls_config *tls_config_new(void);
(define (tls-config-new)
  ((foreign-lambda (c-pointer "struct tls_config") "tls_config_new")))
;; void tls_config_free(struct tls_config *_config);
(define (tls-config-free cfg)
  ((foreign-lambda void "tls_config_free" (c-pointer "struct tls_config")) cfg))

;;const char *tls_default_ca_cert_file(void);
(define (tls-default-ca-cert-file)
  ((foreign-lambda (const c-string) "tls_default_ca_cert_file")))

;; int tls_config_add_keypair_file(struct tls_config *_config,
;;     const char *_cert_file, const char *_key_file);
(define (tls-config-add-keypair-file! cfg cert-file key-file)
  (let ((f (foreign-lambda int "tls_config_add_keypair_file" (c-pointer "struct tls_config") (const c-string) (const c-string))))
    (f cfg cert-file key-file)))
;; int tls_config_add_keypair_mem(struct tls_config *_config, const uint8_t *_cert,
;;     size_t _cert_len, const uint8_t *_key, size_t _key_len);
(define (tls-config-add-keypair-mem! cfg cert cert-len key key-len)
  (let ((f (foreign-lambda int "tls_config_add_keypair_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t)))
    (f cfg cert cert-len key key-len)))
;; int tls_config_add_keypair_ocsp_file(struct tls_config *_config,
;;     const char *_cert_file, const char *_key_file,
;;     const char *_ocsp_staple_file);
(define (tls-config-add-keypair-ocsp-file! cfg cert-file key-file ocsp-staple-file)
  (let ((f (foreign-lambda int "tls_config_add_keypair_ocsp_file" (c-pointer "struct tls_config") (const c-string) (const c-string) (const c-string))))
    (f cfg cert-file key-file ocsp-staple-file)))
;; int tls_config_add_keypair_ocsp_mem(struct tls_config *_config, const uint8_t *_cert,
;;     size_t _cert_len, const uint8_t *_key, size_t _key_len,
;;     const uint8_t *_staple, size_t _staple_len);
(define (tls-config-add-keypair-ocsp-mem! cfg cert cert-len key key-len staple staple-len)
  (let ((f (foreign-lambda int "tls_config_add_keypair_ocsp_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t)))
    (f cfg cert cert-len key key-len staple staple-len)))
;; int tls_config_set_alpn(struct tls_config *_config, const char *_alpn);
(define (tls-config-set-alpn! cfg alpn)
  ((foreign-lambda int "tls_config_set_alpn" (c-pointer "struct tls_config") (const c-string)) cfg alpn))
;; int tls_config_set_ca_file(struct tls_config *_config, const char *_ca_file);
(define (tls-config-set-ca-file! cfg ca-file)
  ((foreign-lambda int "tls_config_set_ca_file" (c-pointer "struct tls_config") (const c-string)) cfg ca-file))
;; int tls_config_set_ca_path(struct tls_config *_config, const char *_ca_path);
(define (tls-config-set-ca-path! cfg ca-path)
  ((foreign-lambda int "tls_config_set_ca_path" (c-pointer "struct tls_config") (const c-string)) cfg ca-path))
;; int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
;;     size_t _len);
(define (tls-config-set-ca-mem! cfg ca len)
  ((foreign-lambda int "tls_config_set_ca_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg ca len))
;; int tls_config_set_cert_file(struct tls_config *_config,
;;     const char *_cert_file);
(define (tls-config-set-cert-file! cfg cert-file)
  ((foreign-lambda int "tls_config_set_cert_file" (c-pointer "struct tls_config") (const c-string)) cfg cert-file))
;; int tls_config_set_cert_mem(struct tls_config *_config, const uint8_t *_cert,
;;     size_t _len);
(define (tls-config-set-cert-mem! cfg cert len)
  ((foreign-lambda int "tls_config_set_cert_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg cert len))
;; int tls_config_set_ciphers(struct tls_config *_config, const char *_ciphers);
(define (tls-config-set-ciphers! cfg ciphers)
  ((foreign-lambda int "tls_config_set_ciphers" (c-pointer "struct tls_config") (const c-string)) cfg ciphers))
;; int tls_config_set_crl_file(struct tls_config *_config, const char *_crl_file);
(define (tls-config-set-crl-file! cfg crl-file)
  ((foreign-lambda int "tls_config_set_crl_file" (c-pointer "struct tls_config") (const c-string)) cfg crl-file))
;; int tls_config_set_crl_mem(struct tls_config *_config, const uint8_t *_crl,
;;     size_t _len);
(define (tls-config-set-crl-mem! cfg crl len)
  ((foreign-lambda int "tls_config_set_crl_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg crl len))
;; int tls_config_set_dheparams(struct tls_config *_config, const char *_params);
(define (tls-config-set-dheparams! cfg params)
  ((foreign-lambda int "tls_config_set_dheparams" (c-pointer "struct tls_config") (const c-string)) cfg params))
;; deprecated
;; int tls_config_set_ecdhecurve(struct tls_config *_config, const char *_curve);
(define (tls-config-set-ecdhecurve! cfg curve)
  ((foreign-lambda int "tls_config_set_ecdhecurve" (c-pointer "struct tls_config") (const c-string)) cfg curve))
;; int tls_config_set_ecdhecurves(struct tls_config *_config, const char *_curves);
(define (tls-config-set-ecdhecurves! cfg curves)
  ((foreign-lambda int "tls_config_set_ecdhecurves" (c-pointer "struct tls_config") (const c-string)) cfg curves))
;; int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
(define (tls-config-set-key-file! cfg key-file)
  ((foreign-lambda int "tls_config_set_key_file" (c-pointer "struct tls_config") (const c-string)) cfg key-file))
;; int tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
;;     size_t _len);
(define (tls-config-set-key-mem! cfg key len)
  ((foreign-lambda int "tls_config_set_key_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg key len))
;; int tls_config_set_keypair_file(struct tls_config *_config,
;;     const char *_cert_file, const char *_key_file);
(define (tls-config-set-keypair-file! cfg cert-file key-file)
  ((foreign-lambda int "tls_config_set_keypair_file" (c-pointer "struct tls_config") (const c-string) (const c-string)) cfg cert-file key-file))
;; int tls_config_set_keypair_mem(struct tls_config *_config, const uint8_t *_cert,
;;     size_t _cert_len, const uint8_t *_key, size_t _key_len);
(define (tls-config-set-keypair-mem! cfg cert cert-len key key-len)
  ((foreign-lambda int "tls_config_set_keypair_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t) cfg cert cert-len key key-len))
;; int tls_config_set_keypair_ocsp_file(struct tls_config *_config,
;;     const char *_cert_file, const char *_key_file, const char *_staple_file);
(define (tls-config-set-keypair-ocsp-file! cfg cert-file key-file staple-file)
  ((foreign-lambda int "tls_config_set_keypair_ocsp_file" (c-pointer "struct tls_config") (const c-string) (const c-string) (const c-string)) cfg cert-file key-file staple-file))
;; int tls_config_set_keypair_ocsp_mem(struct tls_config *_config, const uint8_t *_cert,
;;     size_t _cert_len, const uint8_t *_key, size_t _key_len,
;;     const uint8_t *_staple, size_t staple_len);
(define (tls-config-set-keypair-ocsp-mem! cfg cert cert-len key key-len staple staple-len)
  ((foreign-lambda int "tls_config_set_keypair_ocsp_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t (c-pointer (const unsigned-char)) size_t) cfg cert cert-len key key-len staple staple-len))
;; int tls_config_set_ocsp_staple_mem(struct tls_config *_config,
;;     const uint8_t *_staple, size_t _len);
(define (tls-config-set-ocsp-staple-mem! cfg staple staple-len)
  ((foreign-lambda int "tls_config_set_ocsp_staple_mem" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg staple staple-len))
;; int tls_config_set_ocsp_staple_file(struct tls_config *_config,
;;     const char *_staple_file);
(define (tls-config-set-ocsp-staple-file! cfg staple-file)
  ((foreign-lambda int "tls_config_set_ocsp_staple_file" (c-pointer "struct tls_config") (const c-string)) cfg staple-file))
;; int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
(define (tls-config-set-protocols! cfg protocols)
  ((foreign-lambda int "tls_config_set_protocols" (c-pointer "struct tls_config") unsigned-int32) cfg protocols))
;; int tls_config_set_session_fd(struct tls_config *_config, int _session_fd);
(define (tls-config-set-session-fd! cfg session-fd)
  ((foreign-lambda int "tls_config_set_session_fd" (c-pointer "struct tls_config") int) cfg session-fd))

;; int tls_config_set_verify_depth(struct tls_config *_config, int _verify_depth);
(define (tls-config-set-verify-depth! cfg verify-depth)
  ((foreign-lambda int "tls_config_set_verify_depth" (c-pointer "struct tls_config") int) cfg verify-depth))

;; void tls_config_prefer_ciphers_client(struct tls_config *_config);
(define (tls-config-prefer-ciphers-client! cfg)
  ((foreign-lambda void "tls_config_prefer_ciphers_client" (c-pointer "struct tls_config")) cfg))
;; void tls_config_prefer_ciphers_server(struct tls_config *_config);
(define (tls-config-prefer-ciphers-server! cfg)
  ((foreign-lambda void "tls_config_prefer_ciphers_server" (c-pointer "struct tls_config")) cfg))

;; void tls_config_insecure_noverifycert(struct tls_config *_config);
(define (tls-config-insecure-noverifycert! cfg)
  ((foreign-lambda void "tls_config_insecure_noverifycert" (c-pointer "struct tls_config")) cfg))
;; void tls_config_insecure_noverifyname(struct tls_config *_config);
(define (tls-config-insecure-noverifyname! cfg)
  ((foreign-lambda void "tls_config_insecure_noverifyname" (c-pointer "struct tls_config")) cfg))
;; void tls_config_insecure_noverifytime(struct tls_config *_config);
(define (tls-config-insecure-noverifytime! cfg)
  ((foreign-lambda void "tls_config_insecure_noverifytime" (c-pointer "struct tls_config")) cfg))
;; void tls_config_verify(struct tls_config *_config);
(define (tls-config-verify! cfg)
  ((foreign-lambda void "tls_config_verify" (c-pointer "struct tls_config")) cfg))

;; void tls_config_ocsp_require_stapling(struct tls_config *_config);
(define (tls-config-ocsp-require-stapling! cfg)
  ((foreign-lambda void "tls_config_ocsp_require_stapling" (c-pointer "struct tls_config")) cfg))
;; void tls_config_verify_client(struct tls_config *_config);
(define (tls-config-verify-client! cfg)
  ((foreign-lambda void "tls_config_verify_client" (c-pointer "struct tls_config")) cfg))
;; void tls_config_verify_client_optional(struct tls_config *_config);
(define (tls-config-verify-client-optional! cfg)
  ((foreign-lambda void "tls_config_verify_client_optional" (c-pointer "struct tls_config")) cfg))

;; void tls_config_clear_keys(struct tls_config *_config);
(define (tls-config-clear-keys! cfg)
  ((foreign-lambda void "tls_config_clear_keys" (c-pointer "struct tls_config")) cfg))
;; int tls_config_parse_protocols(uint32_t *_protocols, const char *_protostr);
(define (tls-config-parse-protocols protocols protostr)
  ((foreign-lambda int "tls_config_parse_protocols" (c-pointer unsigned-integer32) (const c-string)) protocols protostr))

;; int tls_config_set_session_id(struct tls_config *_config,
;;     const unsigned char *_session_id, size_t _len);
(define (tls-config-set-session-id! cfg session-id len)
  ((foreign-lambda int "tls_config_set_session_id" (c-pointer "struct tls_config") (c-pointer (const unsigned-char)) size_t) cfg session-id len))
;; int tls_config_set_session_lifetime(struct tls_config *_config, int _lifetime);
(define (tls-config-set-session-lifetime! cfg lifetime)
  ((foreign-lambda int "tls_config_set_session_lifetime" (c-pointer "struct tls_config") int) cfg lifetime))
;; int tls_config_add_ticket_key(struct tls_config *_config, uint32_t _keyrev,
;;     unsigned char *_key, size_t _keylen);
(define (tls-config-add-ticket-key! cfg keyrev key keylen)
  ((foreign-lambda int "tls_config_add_ticket_key" (c-pointer "struct tls_config") unsigned-integer32 (c-pointer unsigned-char) size_t) cfg keyrev key keylen))

;; struct tls *tls_client(void);
(define (tls-client)
  ((foreign-lambda (c-pointer "struct tls") "tls_client")))
;; struct tls *tls_server(void);
(define (tls-server)
  ((foreign-lambda (c-pointer "struct tls") "tls_server")))
;; int tls_configure(struct tls *_ctx, struct tls_config *_config);
(define (tls-configure! ctx cfg)
  (let ((f (foreign-lambda int "tls_configure" (c-pointer "struct tls") (c-pointer "struct tls_config"))))
    (f ctx cfg)))

;; void tls_reset(struct tls *_ctx);
(define (tls-reset! ctx)
  ((foreign-lambda void "tls_reset" (c-pointer "struct tls")) ctx))

;; void tls_free(struct tls *_ctx);
(define (tls-free! ctx)
  ((foreign-lambda void "tls_free" (c-pointer "struct tls")) ctx))

;; int tls_accept_fds(struct tls *_ctx, struct tls **_cctx, int _fd_read,
;;     int _fd_write);
(define (tls-accept-fds ctx cctx fd-read fd-write)
  (let ((f (foreign-lambda int "tls_accept_fds" (c-pointer "struct tls") (c-pointer (c-pointer "struct tls")) int int)))
    (f ctx cctx fd-read fd-write)))
;; int tls_accept_socket(struct tls *_ctx, struct tls **_cctx, int _socket);
(define (tls-accept-socket ctx cctx socket)
  (let ((f (foreign-lambda int "tls_accept_socket" (c-pointer "struct tls") (c-pointer (c-pointer "struct tls")) int)))
    (f ctx cctx socket)))

;; typedef ssize_t (*tls_read_cb)(struct tls *_ctx, void *_buf, size_t _buflen,
;;     void *_cb_arg);

;; int tls_accept_cbs(struct tls *_ctx, struct tls **_cctx,
;;     tls_read_cb _read_cb, tls_write_cb _write_cb, void *_cb_arg);
(define (tls-accept-cbs ctx cctx read-cb write-cb cb-arg)
  (let ((f (foreign-lambda int "tls_accept_cbs" (c-pointer "struct tls") (c-pointer (c-pointer "struct tls")) (function ssize_t ((c-pointer "struct tls") c-pointer size_t c-pointer))
                           (function ssize_t ((c-pointer "struct tls") (const c-pointer) size_t c-pointer)) c-pointer)))
    (f ctx cctx read-cb write-cb cb-arg)))
;; int tls_connect(struct tls *_ctx, const char *_host, const char *_port);
(define (tls-connect ctx host port)
  (let ((f (foreign-lambda int "tls_connect" (c-pointer "struct tls") (const c-string) (const c-string))))
    (f ctx host port)))
;; int tls_connect_fds(struct tls *_ctx, int _fd_read, int _fd_write,
;;     const char *_servername);
(define (tls-connect-fds ctx fd-read fd-write servername)
  (let ((f (foreign-lambda int "tls_connect_fds" (c-pointer "struct tls") int int (const c-string))))
    (f ctx fd-read fd-write servername)))
;; int tls_connect_servername(struct tls *_ctx, const char *_host,
;;     const char *_port, const char *_servername);
(define (tls-connect-servername ctx host port servername)
  (let ((f (foreign-lambda int "tls_connect_servername" (c-pointer "struct tls") (const c-string) (const c-string) (const c-string))))
    (f ctx host port servername)))
;; int tls_connect_socket(struct tls *_ctx, int _s, const char *_servername);
(define (tls-connect-socket ctx s servername)
  (let ((f (foreign-lambda int "tls_connect_socket" (c-pointer "struct tls") int (const c-string))))
    (f ctx s servername)))
;; int tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
;;     tls_write_cb _write_cb, void *_cb_arg, const char *_servername);
(define (tls-connect-cbs ctx read-cb write-cb cb-arg servername)
  (let ((f (foreign-lambda int "tls_connect_cbs" (c-pointer "struct tls") (function ssize_t ((c-pointer "struct tls") c-pointer size_t c-pointer))
                           (function ssize_t ((c-pointer "struct tls") (const c-pointer) size_t c-pointer))  c-pointer (const c-string))))
    (f ctx read-cb write-cb cb-arg servername)))
;; int tls_handshake(struct tls *_ctx);
(define (tls-handshake ctx)
  ((foreign-lambda int "tls_handshake" (c-pointer "struct tls")) ctx))
;; ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
(define (tls-read ctx buf buflen)
  ((foreign-lambda size_t "tls_read" (c-pointer "struct tls") c-pointer size_t) ctx buf buflen))
;; ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
(define (tls-write ctx buf buflen)
  ((foreign-lambda size_t "tls_write" (c-pointer "struct tls") c-pointer size_t) ctx buf buflen))
;; int tls_close(struct tls *_ctx);
(define (tls-close ctx)
  ((foreign-lambda int "tls_close" (c-pointer "struct tls")) ctx))

;; int tls_peer_cert_provided(struct tls *_ctx);
(define (tls-peer-cert-provided? ctx)
  ((foreign-lambda int "tls_peer_cert_provided" (c-pointer "struct tls")) ctx))
;; int tls_peer_cert_contains_name(struct tls *_ctx, const char *_name);
(define (tls-peer-cert-contains-name? ctx name)
  ((foreign-lambda int "tls_peer_cert_contains_name" (c-pointer "struct tls") (const c-string)) ctx name))

;; const char *tls_peer_cert_hash(struct tls *_ctx);
(define (tls-peer-cert-hash ctx)
  ((foreign-lambda (const c-string) "tls_peer_cert_hash" (c-pointer "struct tls")) ctx))
;; const char *tls_peer_cert_issuer(struct tls *_ctx);
(define (tls-peer-cert-issuer ctx)
  ((foreign-lambda (const c-string) "tls_peer_cert_issuer" (c-pointer "struct tls")) ctx))
;; const char *tls_peer_cert_subject(struct tls *_ctx);
(define (tls-peer-cert-subject ctx)
  ((foreign-lambda (const c-string) "tls_peer_cert_subject" (c-pointer "struct tls")) ctx))
;; time_t	tls_peer_cert_notbefore(struct tls *_ctx);
(define (tls-peer-cert-notbefore ctx)
  ((foreign-lambda integer64 "tls_peer_cert_notbefore" (c-pointer "struct tls")) ctx))
;; time_t	tls_peer_cert_notafter(struct tls *_ctx);
(define (tls-peer-cert-notafter ctx)
  ((foreign-lambda integer64 "tls_peer_cert_notafter" (c-pointer "struct tls")) ctx))
;; const uint8_t *tls_peer_cert_chain_pem(struct tls *_ctx, size_t *_len);
(define (tls-peer-cert-chain-pem ctx len)
  ((foreign-lambda (c-pointer (const unsigned-char)) "tls_peer_cert_chain_pem" (c-pointer "struct tls") (c-pointer size_t)) ctx len))

;; const char *tls_conn_alpn_selected(struct tls *_ctx);
(define (tls-conn-alpn-selected ctx)
  ((foreign-lambda (const c-string) "tls_conn_alpn_selected" (c-pointer "struct tls")) ctx))
;; const char *tls_conn_cipher(struct tls *_ctx);
(define (tls-conn-cipher ctx)
  ((foreign-lambda (const c-string) "tls_conn_cipher" (c-pointer "struct tls")) ctx))
;; const char *tls_conn_servername(struct tls *_ctx);
(define (tls-conn-servername ctx)
  ((foreign-lambda (const c-string) "tls_conn_servername" (c-pointer "struct tls")) ctx))
;; int tls_conn_session_resumed(struct tls *_ctx);
(define (tls-conn-session-resumed ctx)
  ((foreign-lambda int "tls_conn_session_resumed" (c-pointer "struct tls")) ctx))
;; const char *tls_conn_version(struct tls *_ctx);
(define (tls-conn-version ctx)
  ((foreign-lambda (const c-string) "tls_conn_version" (c-pointer "struct tls")) ctx))

;; uint8_t *tls_load_file(const char *_file, size_t *_len, char *_password);
(define (tls-load-file file len password)
  ((foreign-lambda (c-pointer unsigned-char) "tls_load_file" (const c-string) (c-pointer size_t) c-string) file len password))

;; void tls_unload_file(uint8_t *_buf, size_t len);
(define (tls-unload-file! buf len)
  ((foreign-lambda void "tls_unload_file" (c-pointer unsigned-char) size_t) buf len))

;; int tls_ocsp_process_response(struct tls *_ctx, const unsigned char *_response,
;;     size_t _size);
(define (tls-ocsp-process-response ctx response size)
  ((foreign-lambda int "tls_ocsp_process_response" (c-pointer "struct tls") (const c-string) size_t) ctx response size))
;; int tls_peer_ocsp_cert_status(struct tls *_ctx);
(define (tls-peer-ocsp-cert-status ctx)
  ((foreign-lambda int "tls_peer_ocsp_cert_status" (c-pointer "struct tls")) ctx))
;; int tls_peer_ocsp_crl_reason(struct tls *_ctx);
(define (tls-peer-ocsp-crl-reason ctx)
  ((foreign-lambda int "tls_peer_ocsp_crl_reason" (c-pointer "struct tls")) ctx))
;; time_t tls_peer_ocsp_next_update(struct tls *_ctx);
(define (tls-peer-ocsp-next-update ctx)
  ((foreign-lambda integer64 "tls_peer_ocsp_next_update" (c-pointer "struct tls")) ctx))
;; int tls_peer_ocsp_response_status(struct tls *_ctx);
(define (tls-peer-ocsp-response-status ctx)
  ((foreign-lambda int "tls_peer_ocsp_response_status" (c-pointer "struct tls")) ctx))
;; const char *tls_peer_ocsp_result(struct tls *_ctx);
(define (tls-peer-ocsp-result ctx)
  ((foreign-lambda c-string "tls_peer_ocsp_result" (c-pointer "struct tls")) ctx))
;; time_t tls_peer_ocsp_revocation_time(struct tls *_ctx);
(define (tls-peer-ocsp-revocation-time ctx)
  ((foreign-lambda integer64 "tls_peer_ocsp_revocation_time" (c-pointer "struct tls")) ctx))
;; time_t tls_peer_ocsp_this_update(struct tls *_ctx);
(define (tls-peer-ocsp-this-update ctx)
  ((foreign-lambda integer64 "tls_peer_ocsp_this_update" (c-pointer "struct tls")) ctx))
;; const char *tls_peer_ocsp_url(struct tls *_ctx);
(define (tls-peer-ocsp-url ctx)
  ((foreign-lambda c-string "tls_peer_ocsp_url" (c-pointer "struct tls")) ctx))
