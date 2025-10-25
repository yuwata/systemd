/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_OPENSSL
#  include <openssl/ec.h>
#  include <openssl/rsa.h>

#  if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#    include <openssl/engine.h>
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ENGINE*, sym_ENGINE_free, ENGINE_freep, NULL);
REENABLE_WARNING;
#  endif

#  ifndef OPENSSL_NO_UI_CONSOLE
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(UI_METHOD*, sym_UI_destroy_method, UI_destroy_methodp, NULL);
#  endif

/* For each error in the OpenSSL thread error queue, log the provided message and the OpenSSL error
 * string. If there are no errors in the OpenSSL thread queue, this logs the message with "No OpenSSL
 * errors." This logs at level debug. Returns -EIO (or -ENOMEM). */
#define log_openssl_errors(fmt, ...) _log_openssl_errors(UNIQ, fmt, ##__VA_ARGS__)
#define _log_openssl_errors(u, fmt, ...)                                \
        ({                                                              \
                size_t UNIQ_T(MAX, u) = 512 /* arbitrary, but openssl doc states it must be >= 256 */; \
                _cleanup_free_ char *UNIQ_T(BUF, u) = malloc(UNIQ_T(MAX, u)); \
                !UNIQ_T(BUF, u)                                         \
                        ? log_oom_debug()                               \
                        : __log_openssl_errors(u, UNIQ_T(BUF, u), UNIQ_T(MAX, u), fmt, ##__VA_ARGS__) \
                        ?: log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": No OpenSSL errors.", ##__VA_ARGS__); \
        })
#define __log_openssl_errors(u, buf, max, fmt, ...)                     \
        ({                                                              \
                int UNIQ_T(R, u) = 0;                                   \
                for (;;) {                                              \
                        unsigned long UNIQ_T(E, u) = sym_ERR_get_error();   \
                        if (UNIQ_T(E, u) == 0)                          \
                                break;                                  \
                        sym_ERR_error_string_n(UNIQ_T(E, u), buf, max);     \
                        UNIQ_T(R, u) = log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": %s", ##__VA_ARGS__, buf); \
                }                                                       \
                UNIQ_T(R, u);                                           \
        })

static void *libcrypto_dl = NULL;

DLSYM_PROTOTYPE(ASN1_ANY_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BIT_STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BMPSTRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_BMPSTRING_new) = NULL;
DLSYM_PROTOTYPE(ASN1_IA5STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_dup) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_free) = NULL;
DLSYM_PROTOTYPE(ASN1_INTEGER_set) = NULL;
DLSYM_PROTOTYPE(ASN1_OBJECT_it) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_free) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_it) = NULL;
DLSYM_PROTOTYPE(ASN1_OCTET_STRING_set) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_new) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_set) = NULL;
DLSYM_PROTOTYPE(ASN1_STRING_set0) = NULL;
DLSYM_PROTOTYPE(ASN1_TIME_free) = NULL;
DLSYM_PROTOTYPE(ASN1_TIME_set) = NULL;
DLSYM_PROTOTYPE(ASN1_TYPE_new) = NULL;
DLSYM_PROTOTYPE(ASN1_get_object) = NULL;
DLSYM_PROTOTYPE(ASN1_item_d2i) = NULL;
DLSYM_PROTOTYPE(ASN1_item_free) = NULL;
DLSYM_PROTOTYPE(ASN1_item_i2d) = NULL;
DLSYM_PROTOTYPE(ASN1_item_new) = NULL;
DLSYM_PROTOTYPE(BIO_ctrl) = NULL;
DLSYM_PROTOTYPE(BIO_find_type) = NULL;
DLSYM_PROTOTYPE(BIO_free) = NULL;
DLSYM_PROTOTYPE(BIO_free_all) = NULL;
DLSYM_PROTOTYPE(BIO_new) = NULL;
DLSYM_PROTOTYPE(BIO_new_mem_buf) = NULL;
DLSYM_PROTOTYPE(BIO_new_socket) = NULL;
DLSYM_PROTOTYPE(BIO_s_mem) = NULL;
DLSYM_PROTOTYPE(BIO_write) = NULL;
DLSYM_PROTOTYPE(BN_CTX_free) = NULL;
DLSYM_PROTOTYPE(BN_CTX_new) = NULL;
DLSYM_PROTOTYPE(BN_bin2bn) = NULL;
DLSYM_PROTOTYPE(BN_bn2bin) = NULL;
DLSYM_PROTOTYPE(BN_bn2nativepad) = NULL;
DLSYM_PROTOTYPE(BN_free) = NULL;
DLSYM_PROTOTYPE(BN_new) = NULL;
DLSYM_PROTOTYPE(BN_num_bits) = NULL;
DLSYM_PROTOTYPE(CRYPTO_free) = NULL;
DLSYM_PROTOTYPE(ECDSA_SIG_free) = NULL;
DLSYM_PROTOTYPE(ECDSA_SIG_new) = NULL;
DLSYM_PROTOTYPE(ECDSA_SIG_set0) = NULL;
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(ECDSA_do_verify) = NULL;
REENABLE_WARNING;
DLSYM_PROTOTYPE(EC_GROUP_free) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get0_generator) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get0_order) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_curve) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_curve_name) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_get_field_type) = NULL;
DLSYM_PROTOTYPE(EC_GROUP_new_by_curve_name) = NULL;
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(EC_KEY_check_key) = NULL;
DLSYM_PROTOTYPE(EC_KEY_free) = NULL;
DLSYM_PROTOTYPE(EC_KEY_new) = NULL;
DLSYM_PROTOTYPE(EC_KEY_set_group) = NULL;
DLSYM_PROTOTYPE(EC_KEY_set_public_key) = NULL;
REENABLE_WARNING;
DLSYM_PROTOTYPE(EC_POINT_free) = NULL;
DLSYM_PROTOTYPE(EC_POINT_new) = NULL;
DLSYM_PROTOTYPE(EC_POINT_oct2point) = NULL;
DLSYM_PROTOTYPE(EC_POINT_point2buf) = NULL;
DLSYM_PROTOTYPE(EC_POINT_point2oct) = NULL;
DLSYM_PROTOTYPE(EC_POINT_set_affine_coordinates) = NULL;
#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(ENGINE_by_id) = NULL;
DLSYM_PROTOTYPE(ENGINE_free) = NULL;
DLSYM_PROTOTYPE(ENGINE_init) = NULL;
DLSYM_PROTOTYPE(ENGINE_load_private_key) = NULL;
REENABLE_WARNING;
#endif
DLSYM_PROTOTYPE(ERR_clear_error) = NULL;
DLSYM_PROTOTYPE(ERR_error_string) = NULL;
DLSYM_PROTOTYPE(ERR_error_string_n) = NULL;
DLSYM_PROTOTYPE(ERR_get_error) = NULL;
DLSYM_PROTOTYPE(ERR_peek_last_error) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_ctrl) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_get_block_size) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_free) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_block_size) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_iv_length) = NULL;
DLSYM_PROTOTYPE(EVP_CIPHER_get_key_length) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DecryptUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_Digest) = NULL;
DLSYM_PROTOTYPE(EVP_DigestFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DigestInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_DigestSign) = NULL;
DLSYM_PROTOTYPE(EVP_DigestSignInit) = NULL;
DLSYM_PROTOTYPE(EVP_DigestUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_DigestVerify) = NULL;
DLSYM_PROTOTYPE(EVP_DigestVerifyInit) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptFinal_ex) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptInit) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptInit_ex) = NULL;
DLSYM_PROTOTYPE(EVP_EncryptUpdate) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_derive) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_KDF_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_get_mac_size) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_final) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_free) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_init) = NULL;
DLSYM_PROTOTYPE(EVP_MAC_update) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_get0_md) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_MD_CTX_set_pkey_ctx) = NULL;
DLSYM_PROTOTYPE(EVP_MD_fetch) = NULL;
DLSYM_PROTOTYPE(EVP_MD_free) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get0_name) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get_size) = NULL;
DLSYM_PROTOTYPE(EVP_MD_get_type) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_free) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_from_name) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_new_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set0_rsa_oaep_label) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_oaep_md) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_rsa_padding) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_CTX_set_signature_md) = NULL;
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(EVP_PKEY_assign) = NULL;
REENABLE_WARNING;
DLSYM_PROTOTYPE(EVP_PKEY_derive) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_derive_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_derive_set_peer) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_encrypt) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_encrypt_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_eq) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_free) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_fromdata) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_fromdata_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get1_encoded_public_key) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_base_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_bits) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_bn_param) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_group_name) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_id) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_get_utf8_string_param) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_keygen) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_keygen_init) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_new) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_new_raw_public_key) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_verify) = NULL;
DLSYM_PROTOTYPE(EVP_PKEY_verify_init) = NULL;
DLSYM_PROTOTYPE(EVP_aes_256_ctr) = NULL;
DLSYM_PROTOTYPE(EVP_aes_256_gcm) = NULL;
DLSYM_PROTOTYPE(EVP_get_cipherbyname) = NULL;
DLSYM_PROTOTYPE(EVP_get_digestbyname) = NULL;
DLSYM_PROTOTYPE(EVP_sha1) = NULL;
DLSYM_PROTOTYPE(EVP_sha256) = NULL;
DLSYM_PROTOTYPE(EVP_sha384) = NULL;
DLSYM_PROTOTYPE(EVP_sha512) = NULL;
DLSYM_PROTOTYPE(HMAC) = NULL;
DLSYM_PROTOTYPE(OBJ_nid2obj) = NULL;
DLSYM_PROTOTYPE(OBJ_nid2sn) = NULL;
DLSYM_PROTOTYPE(OBJ_sn2nid) = NULL;
DLSYM_PROTOTYPE(OBJ_txt2obj) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_new_null) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_pop_free) = NULL;
DLSYM_PROTOTYPE(OPENSSL_sk_push) = NULL;
DLSYM_PROTOTYPE(OSSL_EC_curve_nid2name) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_free) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_new) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_octet_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_push_utf8_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_BLD_to_param) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_BN) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_end) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_octet_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_construct_utf8_string) = NULL;
DLSYM_PROTOTYPE(OSSL_PARAM_free) = NULL;
DLSYM_PROTOTYPE(OSSL_PROVIDER_try_load) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_free) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_CERT) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_INFO_get1_PKEY) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_close) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_expect) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_load) = NULL;
DLSYM_PROTOTYPE(OSSL_STORE_open) = NULL;
DLSYM_PROTOTYPE(PEM_read_PUBKEY) = NULL;
DLSYM_PROTOTYPE(PEM_read_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PEM_read_X509) = NULL;
DLSYM_PROTOTYPE(PEM_read_bio_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PEM_read_bio_X509) = NULL;
DLSYM_PROTOTYPE(PEM_write_PUBKEY) = NULL;
DLSYM_PROTOTYPE(PEM_write_PrivateKey) = NULL;
DLSYM_PROTOTYPE(PKCS5_PBKDF2_HMAC) = NULL;
DLSYM_PROTOTYPE(PKCS7_ATTR_SIGN_it) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_free) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_SIGNER_INFO_set) = NULL;
DLSYM_PROTOTYPE(PKCS7_add0_attrib_signing_time) = NULL;
DLSYM_PROTOTYPE(PKCS7_add1_attrib_digest) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_attrib_content_type) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_attrib_smimecap) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_certificate) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_signed_attribute) = NULL;
DLSYM_PROTOTYPE(PKCS7_add_signer) = NULL;
DLSYM_PROTOTYPE(PKCS7_content_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_ctrl) = NULL;
DLSYM_PROTOTYPE(PKCS7_dataFinal) = NULL;
DLSYM_PROTOTYPE(PKCS7_dataInit) = NULL;
DLSYM_PROTOTYPE(PKCS7_free) = NULL;
DLSYM_PROTOTYPE(PKCS7_new) = NULL;
DLSYM_PROTOTYPE(PKCS7_set_content) = NULL;
DLSYM_PROTOTYPE(PKCS7_set_type) = NULL;
DLSYM_PROTOTYPE(PKCS7_sign) = NULL;
DLSYM_PROTOTYPE(PKCS7_verify) = NULL;
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(RSAPublicKey_dup) = NULL;
DLSYM_PROTOTYPE(RSA_free) = NULL;
DLSYM_PROTOTYPE(RSA_new) = NULL;
DLSYM_PROTOTYPE(RSA_set0_key) = NULL;
DLSYM_PROTOTYPE(RSA_size) = NULL;
REENABLE_WARNING;
DLSYM_PROTOTYPE(SHA512) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_ctrl) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_free) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_new) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_set_default_verify_paths) = NULL;
DLSYM_PROTOTYPE(SSL_CTX_set_options) = NULL;
DLSYM_PROTOTYPE(SSL_SESSION_free) = NULL;
DLSYM_PROTOTYPE(SSL_ctrl) = NULL;
DLSYM_PROTOTYPE(SSL_do_handshake) = NULL;
DLSYM_PROTOTYPE(SSL_free) = NULL;
DLSYM_PROTOTYPE(SSL_get0_param) = NULL;
DLSYM_PROTOTYPE(SSL_get1_session) = NULL;
DLSYM_PROTOTYPE(SSL_get_error) = NULL;
DLSYM_PROTOTYPE(SSL_get_wbio) = NULL;
DLSYM_PROTOTYPE(SSL_new) = NULL;
DLSYM_PROTOTYPE(SSL_read) = NULL;
DLSYM_PROTOTYPE(SSL_set_bio) = NULL;
DLSYM_PROTOTYPE(SSL_set_connect_state) = NULL;
DLSYM_PROTOTYPE(SSL_set_session) = NULL;
DLSYM_PROTOTYPE(SSL_set_verify) = NULL;
DLSYM_PROTOTYPE(SSL_shutdown) = NULL;
DLSYM_PROTOTYPE(SSL_write) = NULL;
DLSYM_PROTOTYPE(TLS_client_method) = NULL;
#ifndef OPENSSL_NO_UI_CONSOLE
DLSYM_PROTOTYPE(UI_OpenSSL) = NULL;
DLSYM_PROTOTYPE(UI_create_method) = NULL;
DLSYM_PROTOTYPE(UI_destroy_method) = NULL;
DLSYM_PROTOTYPE(UI_get0_output_string) = NULL;
DLSYM_PROTOTYPE(UI_get_default_method) = NULL;
DLSYM_PROTOTYPE(UI_get_method) = NULL;
DLSYM_PROTOTYPE(UI_get_string_type) = NULL;
DLSYM_PROTOTYPE(UI_method_get_ex_data) = NULL;
DLSYM_PROTOTYPE(UI_method_get_reader) = NULL;
DLSYM_PROTOTYPE(UI_method_set_ex_data) = NULL;
DLSYM_PROTOTYPE(UI_method_set_reader) = NULL;
DLSYM_PROTOTYPE(UI_set_default_method) = NULL;
DLSYM_PROTOTYPE(UI_set_result) = NULL;
#endif
DLSYM_PROTOTYPE(X509_ALGOR_free) = NULL;
DLSYM_PROTOTYPE(X509_ALGOR_set0) = NULL;
DLSYM_PROTOTYPE(X509_ATTRIBUTE_free) = NULL;
DLSYM_PROTOTYPE(X509_NAME_free) = NULL;
DLSYM_PROTOTYPE(X509_NAME_oneline) = NULL;
DLSYM_PROTOTYPE(X509_NAME_set) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_host) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set1_ip) = NULL;
DLSYM_PROTOTYPE(X509_VERIFY_PARAM_set_hostflags) = NULL;
DLSYM_PROTOTYPE(X509_free) = NULL;
DLSYM_PROTOTYPE(X509_get0_serialNumber) = NULL;
DLSYM_PROTOTYPE(X509_get_issuer_name) = NULL;
DLSYM_PROTOTYPE(X509_get_pubkey) = NULL;
DLSYM_PROTOTYPE(X509_get_signature_info) = NULL;
DLSYM_PROTOTYPE(X509_get_subject_name) = NULL;
DLSYM_PROTOTYPE(X509_gmtime_adj) = NULL;
DLSYM_PROTOTYPE(d2i_ASN1_OCTET_STRING) = NULL;
DLSYM_PROTOTYPE(d2i_ECPKParameters) = NULL;
DLSYM_PROTOTYPE(d2i_PKCS7) = NULL;
DLSYM_PROTOTYPE(d2i_PUBKEY) = NULL;
DLSYM_PROTOTYPE(d2i_PUBKEY_fp) = NULL;
DLSYM_PROTOTYPE(d2i_X509) = NULL;
DLSYM_PROTOTYPE(i2d_PKCS7) = NULL;
DLSYM_PROTOTYPE(i2d_PKCS7_fp) = NULL;
DLSYM_PROTOTYPE(i2d_PUBKEY) = NULL;
DLSYM_PROTOTYPE(i2d_PUBKEY_fp) = NULL;
DLSYM_PROTOTYPE(i2d_PublicKey) = NULL;
DLSYM_PROTOTYPE(i2d_X509) = NULL;
#endif /* HAVE_OPENSSL */

int dlopen_libopenssl(void) {
#if HAVE_OPENSSL
#  if OPENSSL_VERSION_MAJOR >= 3
        ELF_NOTE_DLOPEN("openssl",
                        "Support for cryptography",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libcrypto.so.3");

DISABLE_WARNING_DEPRECATED_DECLARATIONS;
        return dlopen_many_sym_or_warn(
                        &libcrypto_dl,
                        "libcrypto.so.3",
                        LOG_DEBUG,
                        DLSYM_ARG(ASN1_ANY_it),
                        DLSYM_ARG(ASN1_BIT_STRING_it),
                        DLSYM_ARG(ASN1_BMPSTRING_it),
                        DLSYM_ARG(ASN1_BMPSTRING_new),
                        DLSYM_ARG(ASN1_IA5STRING_it),
                        DLSYM_ARG(ASN1_INTEGER_dup),
                        DLSYM_ARG(ASN1_INTEGER_free),
                        DLSYM_ARG(ASN1_INTEGER_set),
                        DLSYM_ARG(ASN1_OBJECT_it),
                        DLSYM_ARG(ASN1_OCTET_STRING_free),
                        DLSYM_ARG(ASN1_OCTET_STRING_it),
                        DLSYM_ARG(ASN1_OCTET_STRING_set),
                        DLSYM_ARG(ASN1_STRING_new),
                        DLSYM_ARG(ASN1_STRING_set),
                        DLSYM_ARG(ASN1_STRING_set0),
                        DLSYM_ARG(ASN1_TIME_free),
                        DLSYM_ARG(ASN1_TIME_set),
                        DLSYM_ARG(ASN1_TYPE_new),
                        DLSYM_ARG(ASN1_get_object),
                        DLSYM_ARG(ASN1_item_d2i),
                        DLSYM_ARG(ASN1_item_free),
                        DLSYM_ARG(ASN1_item_i2d),
                        DLSYM_ARG(ASN1_item_new),
                        DLSYM_ARG(BIO_ctrl),
                        DLSYM_ARG(BIO_find_type),
                        DLSYM_ARG(BIO_free),
                        DLSYM_ARG(BIO_free_all),
                        DLSYM_ARG(BIO_new),
                        DLSYM_ARG(BIO_new_mem_buf),
                        DLSYM_ARG(BIO_new_socket),
                        DLSYM_ARG(BIO_s_mem),
                        DLSYM_ARG(BIO_write),
                        DLSYM_ARG(BN_CTX_free),
                        DLSYM_ARG(BN_CTX_new),
                        DLSYM_ARG(BN_bin2bn),
                        DLSYM_ARG(BN_bn2bin),
                        DLSYM_ARG(BN_bn2nativepad),
                        DLSYM_ARG(BN_free),
                        DLSYM_ARG(BN_new),
                        DLSYM_ARG(BN_num_bits),
                        DLSYM_ARG(CRYPTO_free),
                        DLSYM_ARG(ECDSA_SIG_free),
                        DLSYM_ARG(ECDSA_SIG_new),
                        DLSYM_ARG(ECDSA_SIG_set0),
                        DLSYM_ARG(ECDSA_do_verify),
                        DLSYM_ARG(EC_GROUP_free),
                        DLSYM_ARG(EC_GROUP_get0_generator),
                        DLSYM_ARG(EC_GROUP_get0_order),
                        DLSYM_ARG(EC_GROUP_get_curve),
                        DLSYM_ARG(EC_GROUP_get_curve_name),
                        DLSYM_ARG(EC_GROUP_get_field_type),
                        DLSYM_ARG(EC_GROUP_new_by_curve_name),
                        DLSYM_ARG(EC_KEY_check_key),
                        DLSYM_ARG(EC_KEY_free),
                        DLSYM_ARG(EC_KEY_new),
                        DLSYM_ARG(EC_KEY_set_group),
                        DLSYM_ARG(EC_KEY_set_public_key),
                        DLSYM_ARG(EC_POINT_free),
                        DLSYM_ARG(EC_POINT_new),
                        DLSYM_ARG(EC_POINT_oct2point),
                        DLSYM_ARG(EC_POINT_point2buf),
                        DLSYM_ARG(EC_POINT_point2oct),
                        DLSYM_ARG(EC_POINT_set_affine_coordinates),
#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
                        DLSYM_ARG(ENGINE_by_id),
                        DLSYM_ARG(ENGINE_free),
                        DLSYM_ARG(ENGINE_init),
                        DLSYM_ARG(ENGINE_load_private_key),
#endif
                        DLSYM_ARG(ERR_clear_error),
                        DLSYM_ARG(ERR_error_string),
                        DLSYM_ARG(ERR_error_string_n),
                        DLSYM_ARG(ERR_get_error),
                        DLSYM_ARG(ERR_peek_last_error),
                        DLSYM_ARG(EVP_CIPHER_CTX_ctrl),
                        DLSYM_ARG(EVP_CIPHER_CTX_free),
                        DLSYM_ARG(EVP_CIPHER_CTX_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_CTX_new),
                        DLSYM_ARG(EVP_CIPHER_fetch),
                        DLSYM_ARG(EVP_CIPHER_free),
                        DLSYM_ARG(EVP_CIPHER_get_block_size),
                        DLSYM_ARG(EVP_CIPHER_get_iv_length),
                        DLSYM_ARG(EVP_CIPHER_get_key_length),
                        DLSYM_ARG(EVP_DecryptFinal_ex),
                        DLSYM_ARG(EVP_DecryptInit_ex),
                        DLSYM_ARG(EVP_DecryptUpdate),
                        DLSYM_ARG(EVP_Digest),
                        DLSYM_ARG(EVP_DigestFinal_ex),
                        DLSYM_ARG(EVP_DigestInit_ex),
                        DLSYM_ARG(EVP_DigestSign),
                        DLSYM_ARG(EVP_DigestSignInit),
                        DLSYM_ARG(EVP_DigestUpdate),
                        DLSYM_ARG(EVP_DigestVerify),
                        DLSYM_ARG(EVP_DigestVerifyInit),
                        DLSYM_ARG(EVP_EncryptFinal_ex),
                        DLSYM_ARG(EVP_EncryptInit),
                        DLSYM_ARG(EVP_EncryptInit_ex),
                        DLSYM_ARG(EVP_EncryptUpdate),
                        DLSYM_ARG(EVP_KDF_CTX_free),
                        DLSYM_ARG(EVP_KDF_CTX_new),
                        DLSYM_ARG(EVP_KDF_derive),
                        DLSYM_ARG(EVP_KDF_fetch),
                        DLSYM_ARG(EVP_KDF_free),
                        DLSYM_ARG(EVP_MAC_CTX_free),
                        DLSYM_ARG(EVP_MAC_CTX_get_mac_size),
                        DLSYM_ARG(EVP_MAC_CTX_new),
                        DLSYM_ARG(EVP_MAC_fetch),
                        DLSYM_ARG(EVP_MAC_final),
                        DLSYM_ARG(EVP_MAC_free),
                        DLSYM_ARG(EVP_MAC_init),
                        DLSYM_ARG(EVP_MAC_update),
                        DLSYM_ARG(EVP_MD_CTX_free),
                        DLSYM_ARG(EVP_MD_CTX_get0_md),
                        DLSYM_ARG(EVP_MD_CTX_new),
                        DLSYM_ARG(EVP_MD_CTX_set_pkey_ctx),
                        DLSYM_ARG(EVP_MD_fetch),
                        DLSYM_ARG(EVP_MD_free),
                        DLSYM_ARG(EVP_MD_get0_name),
                        DLSYM_ARG(EVP_MD_get_size),
                        DLSYM_ARG(EVP_MD_get_type),
                        DLSYM_ARG(EVP_PKEY_CTX_free),
                        DLSYM_ARG(EVP_PKEY_CTX_new),
                        DLSYM_ARG(EVP_PKEY_CTX_new_from_name),
                        DLSYM_ARG(EVP_PKEY_CTX_new_id),
                        DLSYM_ARG(EVP_PKEY_CTX_set0_rsa_oaep_label),
                        DLSYM_ARG(EVP_PKEY_CTX_set_ec_paramgen_curve_nid),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_oaep_md),
                        DLSYM_ARG(EVP_PKEY_CTX_set_rsa_padding),
                        DLSYM_ARG(EVP_PKEY_CTX_set_signature_md),
                        DLSYM_ARG(EVP_PKEY_assign),
                        DLSYM_ARG(EVP_PKEY_derive),
                        DLSYM_ARG(EVP_PKEY_derive_init),
                        DLSYM_ARG(EVP_PKEY_derive_set_peer),
                        DLSYM_ARG(EVP_PKEY_encrypt),
                        DLSYM_ARG(EVP_PKEY_encrypt_init),
                        DLSYM_ARG(EVP_PKEY_eq),
                        DLSYM_ARG(EVP_PKEY_free),
                        DLSYM_ARG(EVP_PKEY_fromdata),
                        DLSYM_ARG(EVP_PKEY_fromdata_init),
                        DLSYM_ARG(EVP_PKEY_get1_encoded_public_key),
                        DLSYM_ARG(EVP_PKEY_get_base_id),
                        DLSYM_ARG(EVP_PKEY_get_bits),
                        DLSYM_ARG(EVP_PKEY_get_bn_param),
                        DLSYM_ARG(EVP_PKEY_get_group_name),
                        DLSYM_ARG(EVP_PKEY_get_id),
                        DLSYM_ARG(EVP_PKEY_get_utf8_string_param),
                        DLSYM_ARG(EVP_PKEY_keygen),
                        DLSYM_ARG(EVP_PKEY_keygen_init),
                        DLSYM_ARG(EVP_PKEY_new),
                        DLSYM_ARG(EVP_PKEY_new_raw_public_key),
                        DLSYM_ARG(EVP_PKEY_verify),
                        DLSYM_ARG(EVP_PKEY_verify_init),
                        DLSYM_ARG(EVP_aes_256_ctr),
                        DLSYM_ARG(EVP_aes_256_gcm),
                        DLSYM_ARG(EVP_get_cipherbyname),
                        DLSYM_ARG(EVP_get_digestbyname),
                        DLSYM_ARG(EVP_sha1),
                        DLSYM_ARG(EVP_sha256),
                        DLSYM_ARG(EVP_sha384),
                        DLSYM_ARG(EVP_sha512),
                        DLSYM_ARG(HMAC),
                        DLSYM_ARG(OBJ_nid2obj),
                        DLSYM_ARG(OBJ_nid2sn),
                        DLSYM_ARG(OBJ_sn2nid),
                        DLSYM_ARG(OBJ_txt2obj),
                        DLSYM_ARG(OPENSSL_sk_new_null),
                        DLSYM_ARG(OPENSSL_sk_pop_free),
                        DLSYM_ARG(OPENSSL_sk_push),
                        DLSYM_ARG(OSSL_EC_curve_nid2name),
                        DLSYM_ARG(OSSL_PARAM_BLD_free),
                        DLSYM_ARG(OSSL_PARAM_BLD_new),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_octet_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_push_utf8_string),
                        DLSYM_ARG(OSSL_PARAM_BLD_to_param),
                        DLSYM_ARG(OSSL_PARAM_construct_BN),
                        DLSYM_ARG(OSSL_PARAM_construct_end),
                        DLSYM_ARG(OSSL_PARAM_construct_octet_string),
                        DLSYM_ARG(OSSL_PARAM_construct_utf8_string),
                        DLSYM_ARG(OSSL_PARAM_free),
                        DLSYM_ARG(OSSL_PROVIDER_try_load),
                        DLSYM_ARG(OSSL_STORE_INFO_free),
                        DLSYM_ARG(OSSL_STORE_INFO_get1_CERT),
                        DLSYM_ARG(OSSL_STORE_INFO_get1_PKEY),
                        DLSYM_ARG(OSSL_STORE_close),
                        DLSYM_ARG(OSSL_STORE_expect),
                        DLSYM_ARG(OSSL_STORE_load),
                        DLSYM_ARG(OSSL_STORE_open),
                        DLSYM_ARG(PEM_read_PUBKEY),
                        DLSYM_ARG(PEM_read_PrivateKey),
                        DLSYM_ARG(PEM_read_X509),
                        DLSYM_ARG(PEM_read_bio_PrivateKey),
                        DLSYM_ARG(PEM_read_bio_X509),
                        DLSYM_ARG(PEM_write_PUBKEY),
                        DLSYM_ARG(PEM_write_PrivateKey),
                        DLSYM_ARG(PKCS5_PBKDF2_HMAC),
                        DLSYM_ARG(PKCS7_ATTR_SIGN_it),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_free),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_new),
                        DLSYM_ARG(PKCS7_SIGNER_INFO_set),
                        DLSYM_ARG(PKCS7_add0_attrib_signing_time),
                        DLSYM_ARG(PKCS7_add1_attrib_digest),
                        DLSYM_ARG(PKCS7_add_attrib_content_type),
                        DLSYM_ARG(PKCS7_add_attrib_smimecap),
                        DLSYM_ARG(PKCS7_add_certificate),
                        DLSYM_ARG(PKCS7_add_signed_attribute),
                        DLSYM_ARG(PKCS7_add_signer),
                        DLSYM_ARG(PKCS7_content_new),
                        DLSYM_ARG(PKCS7_ctrl),
                        DLSYM_ARG(PKCS7_dataFinal),
                        DLSYM_ARG(PKCS7_dataInit),
                        DLSYM_ARG(PKCS7_free),
                        DLSYM_ARG(PKCS7_new),
                        DLSYM_ARG(PKCS7_set_content),
                        DLSYM_ARG(PKCS7_set_type),
                        DLSYM_ARG(PKCS7_sign),
                        DLSYM_ARG(PKCS7_verify),
                        DLSYM_ARG(RSAPublicKey_dup),
                        DLSYM_ARG(RSA_free),
                        DLSYM_ARG(RSA_new),
                        DLSYM_ARG(RSA_set0_key),
                        DLSYM_ARG(RSA_size),
                        DLSYM_ARG(SHA512),
                        DLSYM_ARG(SSL_CTX_ctrl),
                        DLSYM_ARG(SSL_CTX_free),
                        DLSYM_ARG(SSL_CTX_new),
                        DLSYM_ARG(SSL_CTX_set_default_verify_paths),
                        DLSYM_ARG(SSL_CTX_set_options),
                        DLSYM_ARG(SSL_SESSION_free),
                        DLSYM_ARG(SSL_ctrl),
                        DLSYM_ARG(SSL_do_handshake),
                        DLSYM_ARG(SSL_free),
                        DLSYM_ARG(SSL_get0_param),
                        DLSYM_ARG(SSL_get1_session),
                        DLSYM_ARG(SSL_get_error),
                        DLSYM_ARG(SSL_get_wbio),
                        DLSYM_ARG(SSL_new),
                        DLSYM_ARG(SSL_read),
                        DLSYM_ARG(SSL_set_bio),
                        DLSYM_ARG(SSL_set_connect_state),
                        DLSYM_ARG(SSL_set_session),
                        DLSYM_ARG(SSL_set_verify),
                        DLSYM_ARG(SSL_shutdown),
                        DLSYM_ARG(SSL_write),
                        DLSYM_ARG(TLS_client_method),
#ifndef OPENSSL_NO_UI_CONSOLE
                        DLSYM_ARG(UI_OpenSSL),
                        DLSYM_ARG(UI_create_method),
                        DLSYM_ARG(UI_destroy_method),
                        DLSYM_ARG(UI_get0_output_string),
                        DLSYM_ARG(UI_get_default_method),
                        DLSYM_ARG(UI_get_method),
                        DLSYM_ARG(UI_get_string_type),
                        DLSYM_ARG(UI_method_get_ex_data),
                        DLSYM_ARG(UI_method_get_reader),
                        DLSYM_ARG(UI_method_set_ex_data),
                        DLSYM_ARG(UI_method_set_reader),
                        DLSYM_ARG(UI_set_default_method),
                        DLSYM_ARG(UI_set_result),
#endif
                        DLSYM_ARG(X509_ALGOR_free),
                        DLSYM_ARG(X509_ALGOR_set0),
                        DLSYM_ARG(X509_ATTRIBUTE_free),
                        DLSYM_ARG(X509_NAME_free),
                        DLSYM_ARG(X509_NAME_oneline),
                        DLSYM_ARG(X509_NAME_set),
                        DLSYM_ARG(X509_VERIFY_PARAM_set1_host),
                        DLSYM_ARG(X509_VERIFY_PARAM_set1_ip),
                        DLSYM_ARG(X509_VERIFY_PARAM_set_hostflags),
                        DLSYM_ARG(X509_free),
                        DLSYM_ARG(X509_get0_serialNumber),
                        DLSYM_ARG(X509_get_issuer_name),
                        DLSYM_ARG(X509_get_pubkey),
                        DLSYM_ARG(X509_get_signature_info),
                        DLSYM_ARG(X509_get_subject_name),
                        DLSYM_ARG(X509_gmtime_adj),
                        DLSYM_ARG(d2i_ASN1_OCTET_STRING),
                        DLSYM_ARG(d2i_ECPKParameters),
                        DLSYM_ARG(d2i_PKCS7),
                        DLSYM_ARG(d2i_PUBKEY),
                        DLSYM_ARG(d2i_PUBKEY_fp),
                        DLSYM_ARG(d2i_X509),
                        DLSYM_ARG(i2d_PKCS7),
                        DLSYM_ARG(i2d_PKCS7_fp),
                        DLSYM_ARG(i2d_PUBKEY),
                        DLSYM_ARG(i2d_PUBKEY_fp),
                        DLSYM_ARG(i2d_PublicKey),
                        DLSYM_ARG(i2d_X509));
REENABLE_WARNING;
#  else
#  endif
#else
        return -EOPNOTSUPP;
#endif
}

#if HAVE_OPENSSL
int openssl_pubkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret) {
        assert(pem);
        assert(ret);

        if (pem_size == SIZE_MAX)
                pem_size = strlen(pem);

        _cleanup_fclose_ FILE *f = NULL;
        f = fmemopen((void*) pem, pem_size, "r");
        if (!f)
                return log_oom_debug();

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = sym_PEM_read_PUBKEY(f, /* x= */ NULL, /* pam_password_cb= */ NULL, /* userdata= */ NULL);
        if (!pkey)
                return log_openssl_errors("Failed to parse PEM");

        *ret = TAKE_PTR(pkey);
        return 0;
}

int openssl_pubkey_to_pem(EVP_PKEY *pkey, char **ret) {
        assert(pkey);
        assert(ret);

        _cleanup_(memstream_done) MemStream m = {};
        FILE *f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        if (sym_PEM_write_PUBKEY(f, pkey) <= 0)
                return -EIO;

        return memstream_finalize(&m, ret, /* ret_size= */ NULL);
}

/* Returns the number of bytes generated by the specified digest algorithm. This can be used only for
 * fixed-size algorithms, e.g. md5, sha1, sha256, etc. Do not use this for variable-sized digest algorithms,
 * e.g. shake128. Returns 0 on success, -EOPNOTSUPP if the algorithm is not supported, or < 0 for any other
 * error. */
int openssl_digest_size(const char *digest_alg, size_t *ret_digest_size) {
        assert(digest_alg);
        assert(ret_digest_size);

        _cleanup_(EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        size_t digest_size = sym_EVP_MD_get_size(md);
        if (digest_size == 0)
                return log_openssl_errors("Failed to get Digest size");

        *ret_digest_size = digest_size;

        return 0;
}

/* Calculate the digest hash value for the provided data, using the specified digest algorithm. Returns 0 on
 * success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any other error. */
int openssl_digest_many(
                const char *digest_alg,
                const struct iovec data[],
                size_t n_data,
                void **ret_digest,
                size_t *ret_digest_size) {

        int r;

        assert(digest_alg);
        assert(data || n_data == 0);
        assert(ret_digest);
        /* ret_digest_size is optional, as caller may already know the digest size */

        _cleanup_(EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = sym_EVP_MD_CTX_new();
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (!sym_EVP_DigestInit_ex(ctx, md, NULL))
                return log_openssl_errors("Failed to initialize EVP_MD_CTX");

        for (size_t i = 0; i < n_data; i++)
                if (!sym_EVP_DigestUpdate(ctx, data[i].iov_base, data[i].iov_len))
                        return log_openssl_errors("Failed to update Digest");

        size_t digest_size;
        r = openssl_digest_size(digest_alg, &digest_size);
        if (r < 0)
                return r;

        _cleanup_free_ void *buf = malloc(digest_size);
        if (!buf)
                return log_oom_debug();

        unsigned size;
        if (!sym_EVP_DigestFinal_ex(ctx, buf, &size))
                return log_openssl_errors("Failed to finalize Digest");

        assert(size == digest_size);

        *ret_digest = TAKE_PTR(buf);
        if (ret_digest_size)
                *ret_digest_size = size;

        return 0;
}

/* Calculate the HMAC digest hash value for the provided data, using the provided key and specified digest
 * algorithm. Returns 0 on success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any
 * other error. */
int openssl_hmac_many(
                const char *digest_alg,
                const void *key,
                size_t key_size,
                const struct iovec data[],
                size_t n_data,
                void **ret_digest,
                size_t *ret_digest_size) {

        assert(digest_alg);
        assert(key);
        assert(data || n_data == 0);
        assert(ret_digest);
        /* ret_digest_size is optional, as caller may already know the digest size */

        _cleanup_(EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        _cleanup_(EVP_MAC_freep) EVP_MAC *mac = sym_EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (!mac)
                return log_openssl_errors("Failed to create new EVP_MAC");

        _cleanup_(EVP_MAC_CTX_freep) EVP_MAC_CTX *ctx = sym_EVP_MAC_CTX_new(mac);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_MAC_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_MAC_PARAM_DIGEST, (char*) digest_alg, 0))
                return log_openssl_errors("Failed to set HMAC OSSL_MAC_PARAM_DIGEST");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build HMAC OSSL_PARAM");

        if (!sym_EVP_MAC_init(ctx, key, key_size, params))
                return log_openssl_errors("Failed to initialize EVP_MAC_CTX");

        for (size_t i = 0; i < n_data; i++)
                if (!sym_EVP_MAC_update(ctx, data[i].iov_base, data[i].iov_len))
                        return log_openssl_errors("Failed to update HMAC");

        size_t digest_size = sym_EVP_MAC_CTX_get_mac_size(ctx);
        if (digest_size == 0)
                return log_openssl_errors("Failed to get HMAC digest size");

        _cleanup_free_ void *buf = malloc(digest_size);
        if (!buf)
                return log_oom_debug();

        size_t size;
        if (!sym_EVP_MAC_final(ctx, buf, &size, digest_size))
                return log_openssl_errors("Failed to finalize HMAC");

        assert(size == digest_size);

        *ret_digest = TAKE_PTR(buf);
        if (ret_digest_size)
                *ret_digest_size = size;

        return 0;
}

/* Symmetric Cipher encryption using the alg-bits-mode cipher, e.g. AES-128-CFB. The key is required and must
 * be at least the minimum required key length for the cipher. The IV is optional but, if provided, it must
 * be at least the minimum iv length for the cipher. If no IV is provided and the cipher requires one, a
 * buffer of zeroes is used. Returns 0 on success, -EOPNOTSUPP if the cipher algorithm is not supported, or <
 * 0 on any other error. */
int openssl_cipher_many(
                const char *alg,
                size_t bits,
                const char *mode,
                const void *key,
                size_t key_size,
                const void *iv,
                size_t iv_size,
                const struct iovec data[],
                size_t n_data,
                void **ret,
                size_t *ret_size) {

        assert(alg);
        assert(bits > 0);
        assert(mode);
        assert(key);
        assert(iv || iv_size == 0);
        assert(data || n_data == 0);
        assert(ret);
        assert(ret_size);

        _cleanup_free_ char *cipher_alg = NULL;
        if (asprintf(&cipher_alg, "%s-%zu-%s", alg, bits, mode) < 0)
                return log_oom_debug();

        _cleanup_(EVP_CIPHER_freep) EVP_CIPHER *cipher = sym_EVP_CIPHER_fetch(NULL, cipher_alg, NULL);
        if (!cipher)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Cipher algorithm '%s' not supported.", cipher_alg);

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *ctx = sym_EVP_CIPHER_CTX_new();
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_CIPHER_CTX");

        /* Verify enough key data was provided. */
        int cipher_key_length = sym_EVP_CIPHER_get_key_length(cipher);
        assert(cipher_key_length >= 0);
        if ((size_t) cipher_key_length > key_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough key bytes provided, require %d", cipher_key_length);

        /* Verify enough IV data was provided or, if no IV was provided, use a zeroed buffer for IV data. */
        int cipher_iv_length = sym_EVP_CIPHER_get_iv_length(cipher);
        assert(cipher_iv_length >= 0);
        _cleanup_free_ void *zero_iv = NULL;
        if (iv_size == 0) {
                zero_iv = malloc0(cipher_iv_length);
                if (!zero_iv)
                        return log_oom_debug();

                iv = zero_iv;
                iv_size = (size_t) cipher_iv_length;
        }
        if ((size_t) cipher_iv_length > iv_size)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough IV bytes provided, require %d", cipher_iv_length);

        if (!sym_EVP_EncryptInit(ctx, cipher, key, iv))
                return log_openssl_errors("Failed to initialize EVP_CIPHER_CTX.");

        int cipher_block_size = sym_EVP_CIPHER_CTX_get_block_size(ctx);
        assert(cipher_block_size > 0);

        _cleanup_free_ uint8_t *buf = NULL;
        size_t size = 0;

        for (size_t i = 0; i < n_data; i++) {
                /* Cipher may produce (up to) input length + cipher block size of output. */
                if (!GREEDY_REALLOC(buf, size + data[i].iov_len + cipher_block_size))
                        return log_oom_debug();

                int update_size;
                if (!sym_EVP_EncryptUpdate(ctx, &buf[size], &update_size, data[i].iov_base, data[i].iov_len))
                        return log_openssl_errors("Failed to update Cipher.");

                size += update_size;
        }

        if (!GREEDY_REALLOC(buf, size + cipher_block_size))
                return log_oom_debug();

        int final_size;
        if (!sym_EVP_EncryptFinal_ex(ctx, &buf[size], &final_size))
                return log_openssl_errors("Failed to finalize Cipher.");

        *ret = TAKE_PTR(buf);
        *ret_size = size + final_size;

        return 0;
}

/* Perform Single-Step (aka "Concat") KDF. Currently, this only supports using the digest for the auxiliary
 * function. The derive_size parameter specifies how many bytes are derived.
 *
 * For more details see: https://www.openssl.org/docs/manmaster/man7/EVP_KDF-SS.html */
int kdf_ss_derive(
                const char *digest,
                const void *key,
                size_t key_size,
                const void *salt,
                size_t salt_size,
                const void *info,
                size_t info_size,
                size_t derive_size,
                void **ret) {

        assert(digest);
        assert(key);
        assert(derive_size > 0);
        assert(ret);

        _cleanup_(EVP_KDF_freep) EVP_KDF *kdf = sym_EVP_KDF_fetch(NULL, "SSKDF", NULL);
        if (!kdf)
                return log_openssl_errors("Failed to create new EVP_KDF");

        _cleanup_(EVP_KDF_CTX_freep) EVP_KDF_CTX *ctx = sym_EVP_KDF_CTX_new(kdf);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_KDF_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        _cleanup_free_ void *buf = malloc(derive_size);
        if (!buf)
                return log_oom_debug();

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, (char*) digest, 0))
                return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_DIGEST");

        if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_KEY, (char*) key, key_size))
                return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_KEY");

        if (salt)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, (char*) salt, salt_size))
                        return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_SALT");

        if (info)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_INFO, (char*) info, info_size))
                        return log_openssl_errors("Failed to add KDF-SS OSSL_KDF_PARAM_INFO");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build KDF-SS OSSL_PARAM");

        if (sym_EVP_KDF_derive(ctx, buf, derive_size, params) <= 0)
                return log_openssl_errors("OpenSSL KDF-SS derive failed");

        *ret = TAKE_PTR(buf);

        return 0;
}

/* Perform Key-Based HMAC KDF. The mode must be "COUNTER" or "FEEDBACK". The parameter naming is from the
 * OpenSSL api, and maps to SP800-108 naming as "...key, salt, info, and seed correspond to KI, Label,
 * Context, and IV (respectively)...". The derive_size parameter specifies how many bytes are derived.
 *
 * For more details see: https://www.openssl.org/docs/manmaster/man7/EVP_KDF-KB.html */
int kdf_kb_hmac_derive(
                const char *mode,
                const char *digest,
                const void *key,
                size_t key_size,
                const void *salt,
                size_t salt_size,
                const void *info,
                size_t info_size,
                const void *seed,
                size_t seed_size,
                size_t derive_size,
                void **ret) {

        assert(mode);
        assert(strcaseeq(mode, "COUNTER") || strcaseeq(mode, "FEEDBACK"));
        assert(digest);
        assert(key || key_size == 0);
        assert(salt || salt_size == 0);
        assert(info || info_size == 0);
        assert(seed || seed_size == 0);
        assert(derive_size > 0);
        assert(ret);

        _cleanup_(EVP_KDF_freep) EVP_KDF *kdf = sym_EVP_KDF_fetch(NULL, "KBKDF", NULL);
        if (!kdf)
                return log_openssl_errors("Failed to create new EVP_KDF");

        _cleanup_(EVP_KDF_CTX_freep) EVP_KDF_CTX *ctx = sym_EVP_KDF_CTX_new(kdf);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_KDF_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_MAC, (char*) "HMAC", 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_MAC");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_MODE, (char*) mode, 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_MODE");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, (char*) digest, 0))
                return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_DIGEST");

        if (key)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_KEY, (char*) key, key_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_KEY");

        if (salt)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, (char*) salt, salt_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_SALT");

        if (info)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_INFO, (char*) info, info_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_INFO");

        if (seed)
                if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SEED, (char*) seed, seed_size))
                        return log_openssl_errors("Failed to add KDF-KB OSSL_KDF_PARAM_SEED");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build KDF-KB OSSL_PARAM");

        _cleanup_free_ void *buf = malloc(derive_size);
        if (!buf)
                return log_oom_debug();

        if (sym_EVP_KDF_derive(ctx, buf, derive_size, params) <= 0)
                return log_openssl_errors("OpenSSL KDF-KB derive failed");

        *ret = TAKE_PTR(buf);

        return 0;
}

int rsa_encrypt_bytes(
                EVP_PKEY *pkey,
                const void *decrypted_key,
                size_t decrypted_key_size,
                void **ret_encrypt_key,
                size_t *ret_encrypt_key_size) {

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        _cleanup_free_ void *b = NULL;
        size_t l;

        ctx = sym_EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to allocate public key context");

        if (sym_EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize public key context");

        if (sym_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return log_openssl_errors("Failed to configure PKCS#1 padding");

        if (sym_EVP_PKEY_encrypt(ctx, NULL, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        b = malloc(l);
        if (!b)
                return -ENOMEM;

        if (sym_EVP_PKEY_encrypt(ctx, b, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        *ret_encrypt_key = TAKE_PTR(b);
        *ret_encrypt_key_size = l;
        return 0;
}

/* Encrypt the key data using RSA-OAEP with the provided label and specified digest algorithm. Returns 0 on
 * success, -EOPNOTSUPP if the digest algorithm is not supported, or < 0 for any other error. */
int rsa_oaep_encrypt_bytes(
                const EVP_PKEY *pkey,
                const char *digest_alg,
                const char *label,
                const void *decrypted_key,
                size_t decrypted_key_size,
                void **ret_encrypt_key,
                size_t *ret_encrypt_key_size) {

        assert(pkey);
        assert(digest_alg);
        assert(label);
        assert(decrypted_key);
        assert(decrypted_key_size > 0);
        assert(ret_encrypt_key);
        assert(ret_encrypt_key_size);

        _cleanup_(EVP_MD_freep) EVP_MD *md = sym_EVP_MD_fetch(NULL, digest_alg, NULL);
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Digest algorithm '%s' not supported.", digest_alg);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new((EVP_PKEY*) pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP padding");

        if (sym_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP MD");

        _cleanup_free_ char *duplabel = strdup(label);
        if (!duplabel)
                return log_oom_debug();

        if (sym_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, duplabel, strlen(duplabel) + 1) <= 0)
                return log_openssl_errors("Failed to configure RSA-OAEP label");
        /* ctx owns this now, don't free */
        TAKE_PTR(duplabel);

        size_t size = 0;
        if (sym_EVP_PKEY_encrypt(ctx, NULL, &size, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine RSA-OAEP encrypted key size");

        _cleanup_free_ void *buf = malloc(size);
        if (!buf)
                return log_oom_debug();

        if (sym_EVP_PKEY_encrypt(ctx, buf, &size, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to RSA-OAEP encrypt");

        *ret_encrypt_key = TAKE_PTR(buf);
        *ret_encrypt_key_size = size;

        return 0;
}

int rsa_pkey_to_suitable_key_size(
                EVP_PKEY *pkey,
                size_t *ret_suitable_key_size) {

        size_t suitable_key_size;
        int bits;

        assert(pkey);
        assert(ret_suitable_key_size);

        /* Analyzes the specified public key and that it is RSA. If so, will return a suitable size for a
         * disk encryption key to encrypt with RSA for use in PKCS#11 security token schemes. */

        if (sym_EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "X.509 certificate does not refer to RSA key.");

        bits = sym_EVP_PKEY_get_bits(pkey);
        log_debug("Bits in RSA key: %i", bits);

        /* We use PKCS#1 padding for the RSA cleartext, hence let's leave some extra space for it, hence only
         * generate a random key half the size of the RSA length */
        suitable_key_size = bits / 8 / 2;

        if (suitable_key_size < 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Uh, RSA key size too short?");

        *ret_suitable_key_size = suitable_key_size;
        return 0;
}

/* Generate RSA public key from provided "n" and "e" values. Numbers "n" and "e" must be provided here
 * in big-endian format, e.g. wrap it with htobe32() for uint32_t. */
int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;

        assert(n);
        assert(n_size != 0);
        assert(e);
        assert(e_size != 0);
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        OSSL_PARAM params[3];

#if __BYTE_ORDER == __BIG_ENDIAN
        params[0] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (void*)n, n_size);
        params[1] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (void*)e, e_size);
#else
        _cleanup_free_ void *native_n = memdup_reverse(n, n_size);
        if (!native_n)
                return log_oom_debug();

        _cleanup_free_ void *native_e = memdup_reverse(e, e_size);
        if (!native_e)
                return log_oom_debug();

        params[0] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, native_n, n_size);
        params[1] = sym_OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, native_e, e_size);
#endif
        params[2] = sym_OSSL_PARAM_construct_end();

        if (sym_EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create RSA EVP_PKEY");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Get the "n" and "e" values from the pkey. The values are returned in "bin" format, i.e. BN_bn2bin(). */
int rsa_pkey_to_n_e(
                const EVP_PKEY *pkey,
                void **ret_n,
                size_t *ret_n_size,
                void **ret_e,
                size_t *ret_e_size) {

        assert(pkey);
        assert(ret_n);
        assert(ret_n_size);
        assert(ret_e);
        assert(ret_e_size);

        _cleanup_(BN_freep) BIGNUM *bn_n = NULL;
        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n))
                return log_openssl_errors("Failed to get RSA n");

        _cleanup_(BN_freep) BIGNUM *bn_e = NULL;
        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e))
                return log_openssl_errors("Failed to get RSA e");

        size_t n_size = sym_BN_num_bytes(bn_n), e_size = sym_BN_num_bytes(bn_e);
        _cleanup_free_ void *n = malloc(n_size), *e = malloc(e_size);
        if (!n || !e)
                return log_oom_debug();

        assert(sym_BN_bn2bin(bn_n, n) == (int) n_size);
        assert(sym_BN_bn2bin(bn_e, e) == (int) e_size);

        *ret_n = TAKE_PTR(n);
        *ret_n_size = n_size;
        *ret_e = TAKE_PTR(e);
        *ret_e_size = e_size;

        return 0;
}

/* Generate ECC public key from provided curve ID and x/y points. */
int ecc_pkey_from_curve_x_y(
                int curve_id,
                const void *x,
                size_t x_size,
                const void *y,
                size_t y_size,
                EVP_PKEY **ret) {

        assert(x);
        assert(y);
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        _cleanup_(BN_freep) BIGNUM *bn_x = sym_BN_bin2bn(x, x_size, NULL);
        if (!bn_x)
                return log_openssl_errors("Failed to create BIGNUM x");

        _cleanup_(BN_freep) BIGNUM *bn_y = sym_BN_bin2bn(y, y_size, NULL);
        if (!bn_y)
                return log_openssl_errors("Failed to create BIGNUM y");

        _cleanup_(EC_GROUP_freep) EC_GROUP *group = sym_EC_GROUP_new_by_curve_name(curve_id);
        if (!group)
                return log_openssl_errors("ECC curve id %d not supported", curve_id);

        _cleanup_(EC_POINT_freep) EC_POINT *point = sym_EC_POINT_new(group);
        if (!point)
                return log_openssl_errors("Failed to create new EC_POINT");

        if (!sym_EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL))
                return log_openssl_errors("Failed to set ECC coordinates");

        if (sym_EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = sym_OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!sym_OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, (char*) sym_OSSL_EC_curve_nid2name(curve_id), 0))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_GROUP_NAME");

        _cleanup_(OPENSSL_freep) void *pbuf = NULL;
        size_t pbuf_len = 0;
        pbuf_len = sym_EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char**) &pbuf, NULL);
        if (pbuf_len == 0)
                return log_openssl_errors("Failed to convert ECC point to buffer");

        if (!sym_OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbuf, pbuf_len))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_PUB_KEY");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = sym_OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build ECC OSSL_PARAM");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create ECC EVP_PKEY");

        *ret = TAKE_PTR(pkey);
        return 0;
}

int ecc_pkey_to_curve_x_y(
                const EVP_PKEY *pkey,
                int *ret_curve_id,
                void **ret_x,
                size_t *ret_x_size,
                void **ret_y,
                size_t *ret_y_size) {

        _cleanup_(BN_freep) BIGNUM *bn_x = NULL, *bn_y = NULL;
        int curve_id;

        assert(pkey);

        size_t name_size;
        if (!sym_EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &name_size))
                return log_openssl_errors("Failed to get ECC group name size");

        _cleanup_free_ char *name = new(char, name_size + 1);
        if (!name)
                return log_oom_debug();

        if (!sym_EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, name_size + 1, NULL))
                return log_openssl_errors("Failed to get ECC group name");

        curve_id = sym_OBJ_sn2nid(name);
        if (curve_id == NID_undef)
                return log_openssl_errors("Failed to get ECC curve id");

        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x))
                return log_openssl_errors("Failed to get ECC point x");

        if (!sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y))
                return log_openssl_errors("Failed to get ECC point y");

        size_t x_size = sym_BN_num_bytes(bn_x), y_size = sym_BN_num_bytes(bn_y);
        _cleanup_free_ void *x = malloc(x_size), *y = malloc(y_size);
        if (!x || !y)
                return log_oom_debug();

        assert(sym_BN_bn2bin(bn_x, x) == (int) x_size);
        assert(sym_BN_bn2bin(bn_y, y) == (int) y_size);

        if (ret_curve_id)
                *ret_curve_id = curve_id;
        if (ret_x)
                *ret_x = TAKE_PTR(x);
        if (ret_x_size)
                *ret_x_size = x_size;
        if (ret_y)
                *ret_y = TAKE_PTR(y);
        if (ret_y_size)
                *ret_y_size = y_size;

        return 0;
}

/* Generate a new ECC key for the specified ECC curve id. */
int ecc_pkey_new(int curve_id, EVP_PKEY **ret) {
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_keygen_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_id) <= 0)
                return log_openssl_errors("Failed to set ECC curve %d", curve_id);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_openssl_errors("Failed to generate ECC key");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Perform ECDH to derive an ECC shared secret between the provided private key and public peer key. For two
 * keys, this will result in the same shared secret in either direction; ECDH using Alice's private key and
 * Bob's public (peer) key will result in the same shared secret as ECDH using Bob's private key and Alice's
 * public (peer) key. On success, this returns 0 and provides the shared secret; otherwise this returns an
 * error. */
int ecc_ecdh(const EVP_PKEY *private_pkey,
             const EVP_PKEY *peer_pkey,
             void **ret_shared_secret,
             size_t *ret_shared_secret_size) {

        assert(private_pkey);
        assert(peer_pkey);
        assert(ret_shared_secret);
        assert(ret_shared_secret_size);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new((EVP_PKEY*) private_pkey, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (sym_EVP_PKEY_derive_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (sym_EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*) peer_pkey) <= 0)
                return log_openssl_errors("Failed to set ECC derive peer");

        size_t shared_secret_size;
        if (sym_EVP_PKEY_derive(ctx, NULL, &shared_secret_size) <= 0)
                return log_openssl_errors("Failed to get ECC shared secret size");

        _cleanup_(erase_and_freep) void *shared_secret = malloc(shared_secret_size);
        if (!shared_secret)
                return log_oom_debug();

        if (sym_EVP_PKEY_derive(ctx, (unsigned char*) shared_secret, &shared_secret_size) <= 0)
                return log_openssl_errors("Failed to derive ECC shared secret");

        *ret_shared_secret = TAKE_PTR(shared_secret);
        *ret_shared_secret_size = shared_secret_size;

        return 0;
}

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX* m = NULL;
        _cleanup_free_ void *d = NULL, *h = NULL;
        int sz, lsz, msz;
        unsigned umsz;
        unsigned char *dd;

        /* Calculates a message digest of the DER encoded public key */

        assert(pk);
        assert(md);
        assert(ret);
        assert(ret_size);

        sz = sym_i2d_PublicKey(pk, NULL);
        if (sz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        dd = d = malloc(sz);
        if (!d)
                return log_oom_debug();

        lsz = sym_i2d_PublicKey(pk, &dd);
        if (lsz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        m = sym_EVP_MD_CTX_new();
        if (!m)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (sym_EVP_DigestInit_ex(m, md, NULL) != 1)
                return log_openssl_errors("Failed to initialize %s context", sym_EVP_MD_get0_name(md));

        if (sym_EVP_DigestUpdate(m, d, lsz) != 1)
                return log_openssl_errors("Failed to run %s context", sym_EVP_MD_get0_name(md));

        msz = sym_EVP_MD_get_size(md);
        assert(msz > 0);

        h = malloc(msz);
        if (!h)
                return log_oom_debug();

        umsz = msz;
        if (sym_EVP_DigestFinal_ex(m, h, &umsz) != 1)
                return log_openssl_errors("Failed to finalize hash context");

        assert(umsz == (unsigned) msz);

        *ret = TAKE_PTR(h);
        *ret_size = msz;

        return 0;
}

int digest_and_sign(
                const EVP_MD *md,
                EVP_PKEY *privkey,
                const void *data, size_t size,
                void **ret, size_t *ret_size) {

        int r;

        assert(privkey);
        assert(ret);
        assert(ret_size);

        if (size == 0)
                data = ""; /* make sure to pass a valid pointer to OpenSSL */
        else {
                assert(data);

                if (size == SIZE_MAX) /* If SIZE_MAX input is a string whose size we determine automatically */
                        size = strlen(data);
        }

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX* mdctx = sym_EVP_MD_CTX_new();
        if (!mdctx)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (sym_EVP_DigestSignInit(mdctx, NULL, md, NULL, privkey) != 1) {
                /* Distro security policies often disable support for SHA-1. Let's return a recognizable
                 * error for that case. */
                bool invalid_digest = ERR_GET_REASON(sym_ERR_peek_last_error()) == EVP_R_INVALID_DIGEST;
                r = log_openssl_errors("Failed to initialize signature context");
                return invalid_digest ? -EADDRNOTAVAIL : r;
}

        /* Determine signature size */
        size_t ss;
        if (sym_EVP_DigestSign(mdctx, NULL, &ss, data, size) != 1)
                return log_openssl_errors("Failed to determine size of signature");

        _cleanup_free_ void *sig = malloc(ss);
        if (!sig)
                return log_oom_debug();

        if (sym_EVP_DigestSign(mdctx, sig, &ss, data, size) != 1)
                return log_openssl_errors("Failed to sign data");

        *ret = TAKE_PTR(sig);
        *ret_size = ss;
        return 0;
}

int pkcs7_new(X509 *certificate, EVP_PKEY *private_key, const char *hash_algorithm, PKCS7 **ret_p7, PKCS7_SIGNER_INFO **ret_si) {
        assert(certificate);
        assert(ret_p7);

        /* This function sets up a new PKCS7 signing context. If a private key is provided, the context is
         * set up for "in-band" signing with PKCS7_dataFinal(). If a private key is not provided, the context
         * is set up for "out-of-band" signing, meaning the signature has to be provided by the user and
         * copied into the signer info's "enc_digest" field. If the signing hash algorithm is not provided,
         * SHA-256 is used. */

        _cleanup_(PKCS7_freep) PKCS7 *p7 = sym_PKCS7_new();
        if (!p7)
                return log_oom();

        if (sym_PKCS7_set_type(p7, NID_pkcs7_signed) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set PKCS7 type: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        if (sym_PKCS7_content_new(p7, NID_pkcs7_data) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set PKCS7 content: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        if (sym_PKCS7_add_certificate(p7, certificate) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set PKCS7 certificate: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        int x509_pknid = 0;
        if (sym_X509_get_signature_info(certificate, NULL, &x509_pknid, NULL, NULL) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to get X509 digest NID: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        const EVP_MD *md = sym_EVP_get_digestbyname(hash_algorithm ?: "SHA256");
        if (!md)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to get digest algorithm '%s'",
                                       hash_algorithm ?: "SHA256");

        _cleanup_(PKCS7_SIGNER_INFO_freep) PKCS7_SIGNER_INFO *si = sym_PKCS7_SIGNER_INFO_new();
        if (!si)
                return log_oom();

        if (private_key) {
                if (sym_PKCS7_SIGNER_INFO_set(si, certificate, private_key, md) <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to configure signer info: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));
        } else {
                if (sym_ASN1_INTEGER_set(si->version, 1) == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set signer info version: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));

                if (sym_X509_NAME_set(&si->issuer_and_serial->issuer, sym_X509_get_issuer_name(certificate)) == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set signer info issuer: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));

                sym_ASN1_INTEGER_free(si->issuer_and_serial->serial);
                si->issuer_and_serial->serial = sym_ASN1_INTEGER_dup(sym_X509_get0_serialNumber(certificate));
                if (!si->issuer_and_serial->serial)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set signer info serial: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));

                if (sym_X509_ALGOR_set0(si->digest_alg, sym_OBJ_nid2obj(sym_EVP_MD_get_type(md)), V_ASN1_NULL, NULL) == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set signer info digest algorithm: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));

                if (sym_X509_ALGOR_set0(si->digest_enc_alg, sym_OBJ_nid2obj(x509_pknid), V_ASN1_NULL, NULL) == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set signer info signing algorithm: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));
        }

        if (sym_PKCS7_add_signer(p7, si) == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set PKCS7 signer info: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        *ret_p7 = TAKE_PTR(p7);
        if (ret_si)
                /* We do not pass ownership here, 'si' object remains owned by 'p7' object. */
                *ret_si = si;

        TAKE_PTR(si);

        return 0;
}

int string_hashsum(
                const char *s,
                size_t len,
                const char *md_algorithm,
                char **ret) {

        _cleanup_free_ void *hash = NULL;
        size_t hash_size;
        _cleanup_free_ char *enc = NULL;
        int r;

        assert(s || len == 0);
        assert(md_algorithm);
        assert(ret);

        r = openssl_digest(md_algorithm, s, len, &hash, &hash_size);
        if (r < 0)
                return r;

        enc = hexmem(hash, hash_size);
        if (!enc)
                return -ENOMEM;

        *ret = TAKE_PTR(enc);
        return 0;
}

static int ecc_pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_new = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_free_ unsigned char *saved_key = NULL;
        size_t decrypted_key_size, saved_key_size;
        int r;

        _cleanup_free_ char *curve_name = NULL;
        size_t len = 0;

        if (sym_EVP_PKEY_get_group_name(pkey, NULL, 0, &len) != 1 || len == 0)
                return log_openssl_errors("Failed to determine PKEY group name length");

        len++;
        curve_name = new(char, len);
        if (!curve_name)
                return log_oom_debug();

        if (sym_EVP_PKEY_get_group_name(pkey, curve_name, len, &len) != 1)
                return log_openssl_errors("Failed to get PKEY group name");

        r = ecc_pkey_new(sym_OBJ_sn2nid(curve_name), &pkey_new);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate a new EC keypair: %m");

        r = ecc_ecdh(pkey_new, pkey, &decrypted_key, &decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to derive shared secret: %m");

        /* EVP_PKEY_get1_encoded_public_key() always returns uncompressed format of EC points.
           See https://github.com/openssl/openssl/discussions/22835 */
        saved_key_size = sym_EVP_PKEY_get1_encoded_public_key(pkey_new, &saved_key);
        if (saved_key_size == 0)
                return log_openssl_errors("Failed to convert the generated public key to SEC1 format");

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_saved_key = TAKE_PTR(saved_key);
        *ret_saved_key_size = saved_key_size;
        return 0;
}

static int rsa_pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_free_ void *saved_key = NULL;
        size_t decrypted_key_size, saved_key_size;
        int r;

        r = rsa_pkey_to_suitable_key_size(pkey, &decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine RSA public key size.");

        log_debug("Generating %zu bytes random key.", decrypted_key_size);

        decrypted_key = malloc(decrypted_key_size);
        if (!decrypted_key)
                return log_oom_debug();

        r = crypto_random_bytes(decrypted_key, decrypted_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate random key: %m");

        r = rsa_encrypt_bytes(pkey, decrypted_key, decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to encrypt random key: %m");

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_saved_key = TAKE_PTR(saved_key);
        *ret_saved_key_size = saved_key_size;
        return 0;
}

int pkey_generate_volume_keys(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        assert(pkey);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);
        assert(ret_saved_key);
        assert(ret_saved_key_size);

        int type = sym_EVP_PKEY_get_base_id(pkey);
        switch (type) {

        case EVP_PKEY_RSA:
                return rsa_pkey_generate_volume_keys(pkey, ret_decrypted_key, ret_decrypted_key_size, ret_saved_key, ret_saved_key_size);

        case EVP_PKEY_EC:
                return ecc_pkey_generate_volume_keys(pkey, ret_decrypted_key, ret_decrypted_key_size, ret_saved_key, ret_saved_key_size);

        case NID_undef:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine a type of public key.");

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported public key type: %s", sym_OBJ_nid2sn(type));
        }
}

static int load_key_from_provider(
                const char *provider,
                const char *private_key_uri,
                EVP_PKEY **ret) {

        assert(provider);
        assert(private_key_uri);
        assert(ret);

        /* Load the provider so that this can work without any custom written configuration in /etc/.
         * Also load the 'default' as that seems to be the recommendation. */
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, provider, /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider '%s'", provider);
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, "default", /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider 'default'");

        _cleanup_(OSSL_STORE_closep) OSSL_STORE_CTX *store = sym_OSSL_STORE_open(
                        private_key_uri,
                        /*ui_method=*/ NULL,
                        /*ui_method=*/ NULL,
                        /* post_process= */ NULL,
                        /* post_process_data= */ NULL);
        if (!store)
                return log_openssl_errors("Failed to open OpenSSL store via '%s'", private_key_uri);

        if (sym_OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY) == 0)
                return log_openssl_errors("Failed to filter store by private keys");

        _cleanup_(OSSL_STORE_INFO_freep) OSSL_STORE_INFO *info = sym_OSSL_STORE_load(store);
        if (!info)
                return log_openssl_errors("Failed to load OpenSSL store via '%s'", private_key_uri);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = sym_OSSL_STORE_INFO_get1_PKEY(info);
        if (!private_key)
                return log_openssl_errors("Failed to load private key via '%s'", private_key_uri);

        *ret = TAKE_PTR(private_key);

        return 0;
}

static int load_key_from_engine(const char *engine, const char *private_key_uri, EVP_PKEY **ret) {
        assert(engine);
        assert(private_key_uri);
        assert(ret);

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
        DISABLE_WARNING_DEPRECATED_DECLARATIONS;
        _cleanup_(ENGINE_freep) ENGINE *e = sym_ENGINE_by_id(engine);
        if (!e)
                return log_openssl_errors("Failed to load signing engine '%s'", engine);

        if (sym_ENGINE_init(e) == 0)
                return log_openssl_errors("Failed to initialize signing engine '%s'", engine);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = sym_ENGINE_load_private_key(e, private_key_uri, /*ui_method=*/ NULL, /*callback_data=*/ NULL);
        if (!private_key)
                return log_openssl_errors("Failed to load private key from '%s'", private_key_uri);
        REENABLE_WARNING;

        *ret = TAKE_PTR(private_key);

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

#ifndef OPENSSL_NO_UI_CONSOLE
static int openssl_ask_password_ui_read(UI *ui, UI_STRING *uis) {
        int r;

        switch(sym_UI_get_string_type(uis)) {
        case UIT_PROMPT: {
                /* If no ask password request was configured use the default openssl UI. */
                AskPasswordRequest *req = (AskPasswordRequest*) sym_UI_method_get_ex_data(sym_UI_get_method(ui), 0);
                if (!req)
                        return (sym_UI_method_get_reader(sym_UI_OpenSSL()))(ui, uis);

                req->message = sym_UI_get0_output_string(uis);

                _cleanup_strv_free_ char **l = NULL;
                r = ask_password_auto(req, ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE, &l);
                if (r < 0) {
                        log_error_errno(r, "Failed to query for PIN: %m");
                        return 0;
                }

                if (strv_length(l) != 1) {
                        log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected only a single password/pin.");
                        return 0;
                }

                if (sym_UI_set_result(ui, uis, *l) != 0) {
                        log_openssl_errors("Failed to set user interface result");
                        return 0;
                }

                return 1;
        }
        default:
                return (sym_UI_method_get_reader(sym_UI_OpenSSL()))(ui, uis);
        }
}
#endif

static int openssl_load_private_key_from_file(const char *path, EVP_PKEY **ret) {
        _cleanup_(erase_and_freep) char *rawkey = NULL;
        _cleanup_(BIO_freep) BIO *kb = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pk = NULL;
        size_t rawkeysz;
        int r;

        assert(path);
        assert(ret);

        r = read_full_file_full(
                        AT_FDCWD, path, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        &rawkey, &rawkeysz);
        if (r < 0)
                return log_debug_errno(r, "Failed to read key file '%s': %m", path);

        kb = sym_BIO_new_mem_buf(rawkey, rawkeysz);
        if (!kb)
                return log_oom_debug();

        pk = sym_PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
        if (!pk)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse PEM private key: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        if (ret)
                *ret = TAKE_PTR(pk);

        return 0;
}

static int openssl_ask_password_ui_new(const AskPasswordRequest *request, OpenSSLAskPasswordUI **ret) {
        assert(ret);

#ifndef OPENSSL_NO_UI_CONSOLE
        _cleanup_(UI_destroy_methodp) UI_METHOD *method = sym_UI_create_method("systemd-ask-password");
        if (!method)
                return log_openssl_errors("Failed to initialize openssl user interface");

        if (sym_UI_method_set_reader(method, openssl_ask_password_ui_read) != 0)
                return log_openssl_errors("Failed to set openssl user interface reader");

        OpenSSLAskPasswordUI *ui = new(OpenSSLAskPasswordUI, 1);
        if (!ui)
                return log_oom_debug();

        *ui = (OpenSSLAskPasswordUI) {
                .method = TAKE_PTR(method),
                .request = *request,
        };

        sym_UI_set_default_method(ui->method);

        if (sym_UI_method_set_ex_data(ui->method, 0, &ui->request) == 0)
                return log_openssl_errors("Failed to set extra data for UI method");

        *ret = TAKE_PTR(ui);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

static int load_x509_certificate_from_file(const char *path, X509 **ret) {
        _cleanup_free_ char *rawcert = NULL;
        _cleanup_(X509_freep) X509 *cert = NULL;
        _cleanup_(BIO_freep) BIO *cb = NULL;
        size_t rawcertsz;
        int r;

        assert(path);
        assert(ret);

        r = read_full_file_full(
                        AT_FDCWD, path, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        &rawcert, &rawcertsz);
        if (r < 0)
                return log_debug_errno(r, "Failed to read certificate file '%s': %m", path);

        cb = sym_BIO_new_mem_buf(rawcert, rawcertsz);
        if (!cb)
                return log_oom_debug();

        cert = sym_PEM_read_bio_X509(cb, NULL, NULL, NULL);
        if (!cert)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse X.509 certificate: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        if (ret)
                *ret = TAKE_PTR(cert);

        return 0;
}

static int load_x509_certificate_from_provider(const char *provider, const char *certificate_uri, X509 **ret) {
        assert(provider);
        assert(certificate_uri);
        assert(ret);

        /* Load the provider so that this can work without any custom written configuration in /etc/.
         * Also load the 'default' as that seems to be the recommendation. */
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, provider, /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider '%s'", provider);
        if (!sym_OSSL_PROVIDER_try_load(/* ctx= */ NULL, "default", /* retain_fallbacks= */ true))
                return log_openssl_errors("Failed to load OpenSSL provider 'default'");

        _cleanup_(OSSL_STORE_closep) OSSL_STORE_CTX *store = sym_OSSL_STORE_open(
                        certificate_uri,
                        /*ui_method=*/ NULL,
                        /*ui_method=*/ NULL,
                        /* post_process= */ NULL,
                        /* post_process_data= */ NULL);
        if (!store)
                return log_openssl_errors("Failed to open OpenSSL store via '%s'", certificate_uri);

        if (sym_OSSL_STORE_expect(store, OSSL_STORE_INFO_CERT) == 0)
                return log_openssl_errors("Failed to filter store by X.509 certificates");

        _cleanup_(OSSL_STORE_INFO_freep) OSSL_STORE_INFO *info = sym_OSSL_STORE_load(store);
        if (!info)
                return log_openssl_errors("Failed to load OpenSSL store via '%s'", certificate_uri);

        _cleanup_(X509_freep) X509 *cert = sym_OSSL_STORE_INFO_get1_CERT(info);
        if (!cert)
                return log_openssl_errors("Failed to load certificate via '%s'", certificate_uri);

        *ret = TAKE_PTR(cert);

        return 0;
}
#endif /* HAVE_OPENSSL */

OpenSSLAskPasswordUI* openssl_ask_password_ui_free(OpenSSLAskPasswordUI *ui) {
#if HAVE_OPENSSL && !defined(OPENSSL_NO_UI_CONSOLE)
        if (!ui)
                return NULL;

        assert(sym_UI_get_default_method() == ui->method);
        sym_UI_set_default_method(sym_UI_OpenSSL());
        sym_UI_destroy_method(ui->method);
        return mfree(ui);
#else
        assert(ui == NULL);
        return NULL;
#endif
}

int x509_fingerprint(X509 *cert, uint8_t buffer[static SHA256_DIGEST_SIZE]) {
#if HAVE_OPENSSL
        _cleanup_free_ uint8_t *der = NULL;
        int dersz;

        assert(cert);

        dersz = sym_i2d_X509(cert, &der);
        if (dersz < 0)
                return log_openssl_errors("Unable to convert PEM certificate to DER format");

        sha256_direct(der, dersz, buffer);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot calculate X509 fingerprint.");
#endif
}

int openssl_load_x509_certificate(
                CertificateSourceType certificate_source_type,
                const char *certificate_source,
                const char *certificate,
                X509 **ret) {
#if HAVE_OPENSSL
        int r;

        assert(certificate);

        switch (certificate_source_type) {

        case OPENSSL_CERTIFICATE_SOURCE_FILE:
                r = load_x509_certificate_from_file(certificate, ret);
                break;
        case OPENSSL_CERTIFICATE_SOURCE_PROVIDER:
                r = load_x509_certificate_from_provider(certificate_source, certificate, ret);
                break;
        default:
                assert_not_reached();
        }
        if (r < 0)
                return log_debug_errno(
                                r,
                                "Failed to load certificate '%s' from OpenSSL certificate source %s: %m",
                                certificate,
                                certificate_source);

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot load X509 certificate.");
#endif
}

int openssl_load_private_key(
                KeySourceType private_key_source_type,
                const char *private_key_source,
                const char *private_key,
                const AskPasswordRequest *request,
                EVP_PKEY **ret_private_key,
                OpenSSLAskPasswordUI **ret_user_interface) {
#if HAVE_OPENSSL
        int r;

        assert(private_key);
        assert(request);
        assert(ret_private_key);

        if (private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                r = openssl_load_private_key_from_file(private_key, ret_private_key);
                if (r < 0)
                        return r;

                if (ret_user_interface)
                        *ret_user_interface = NULL;
        } else {
                _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
                r = openssl_ask_password_ui_new(request, &ui);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate ask-password user interface: %m");

                switch (private_key_source_type) {

                case OPENSSL_KEY_SOURCE_ENGINE:
                        r = load_key_from_engine(private_key_source, private_key, ret_private_key);
                        break;
                case OPENSSL_KEY_SOURCE_PROVIDER:
                        r = load_key_from_provider(private_key_source, private_key, ret_private_key);
                        break;
                default:
                        assert_not_reached();
                }
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to load key '%s' from OpenSSL private key source %s: %m",
                                        private_key,
                                        private_key_source);

                if (ret_user_interface)
                        *ret_user_interface = TAKE_PTR(ui);
        }

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL is not supported, cannot load private key.");
#endif
}

int parse_openssl_certificate_source_argument(
                const char *argument,
                char **certificate_source,
                CertificateSourceType *certificate_source_type) {

        CertificateSourceType type;
        const char *e = NULL;
        int r;

        assert(argument);
        assert(certificate_source);
        assert(certificate_source_type);

        if (streq(argument, "file"))
                type = OPENSSL_CERTIFICATE_SOURCE_FILE;
        else if ((e = startswith(argument, "provider:")))
                type = OPENSSL_CERTIFICATE_SOURCE_PROVIDER;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid certificate source '%s'", argument);

        r = free_and_strdup_warn(certificate_source, e);
        if (r < 0)
                return r;

        *certificate_source_type = type;

        return 0;
}

int parse_openssl_key_source_argument(
                const char *argument,
                char **private_key_source,
                KeySourceType *private_key_source_type) {

        KeySourceType type;
        const char *e = NULL;
        int r;

        assert(argument);
        assert(private_key_source);
        assert(private_key_source_type);

        if (streq(argument, "file"))
                type = OPENSSL_KEY_SOURCE_FILE;
        else if ((e = startswith(argument, "engine:")))
                type = OPENSSL_KEY_SOURCE_ENGINE;
        else if ((e = startswith(argument, "provider:")))
                type = OPENSSL_KEY_SOURCE_PROVIDER;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid private key source '%s'", argument);

        r = free_and_strdup_warn(private_key_source, e);
        if (r < 0)
                return r;

        *private_key_source_type = type;

        return 0;
}
