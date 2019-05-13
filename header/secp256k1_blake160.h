#ifndef CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160
#define CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "protocol_reader.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(Ckb_Protocol, x)

#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -1
#define ERROR_WRONG_HEX_ENCODING -2
#define ERROR_SECP_ABORT -3
#define ERROR_LOAD_TX -4
#define ERROR_PARSE_TX -5
#define ERROR_SECP_INITIALIZE -6
#define ERROR_SECP_PARSE_PUBKEY -7
#define ERROR_SECP_PARSE_SIGNATURE -8
#define ERROR_PARSE_SIGHASH_TYPE -9
#define ERROR_LOAD_SELF_OUT_POINT -10
#define ERROR_PARSE_SELF_OUT_POINT -11
#define ERROR_LOAD_SELF_LOCK_HASH -12
#define ERROR_LOAD_LOCK_HASH -13
#define ERROR_INVALID_SIGHASH_TYPE -14
#define ERROR_SECP_VERIFICATION -15
#define ERROR_PARSE_SINGLE_INDEX -16
#define ERROR_SINGLE_INDEX_IS_INVALID -17
#define ERROR_PUBKEY_BLAKE160_HASH -18
#define ERROR_PUBKEY_BLAKE160_HASH_LENGTH -19
#define ERROR_LOAD_SCRIPT_HASH -20
#define ERROR_LOAD_SINCE -21

#define SIGHASH_ALL 0x1
#define SIGHASH_NONE 0x2
#define SIGHASH_SINGLE 0x3
#define SIGHASH_MULTIPLE 0x4
#define SIGHASH_ANYONECANPAY 0x80

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

#define PUBKEY_SIZE 33
#define SIGNATURE_SIZE 64

#define CUSTOM_ABORT 1
#define CUSTOM_PRINT_ERR 1

void custom_abort()
{
  syscall(SYS_exit, ERROR_SECP_ABORT, 0, 0, 0, 0, 0);
}

int custom_print_err(const char * arg, ...)
{
  (void) arg;
  return 0;
}

#include <secp256k1_static.h>
/*
 * We are including secp256k1 implementation directly so gcc can strip
 * unused functions. For some unknown reasons, if we link in libsecp256k1.a
 * directly, the final binary will include all functions rather than those used.
 */
#include <secp256k1.c>

int char_to_int(char ch)
{
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  return ERROR_WRONG_HEX_ENCODING;
}

int hex_to_bin(char* buf, size_t buf_len, const char* hex)
{
  int i = 0;

  for (; i < buf_len && hex[i * 2] != '\0' && hex[i * 2 + 1] != '\0'; i++) {
    int a = char_to_int(hex[i * 2]);
    int b = char_to_int(hex[i * 2 + 1]);

    if (a < 0 || b < 0) {
      return ERROR_WRONG_HEX_ENCODING;
    }

    buf[i] = ((a & 0xF) << 4) | (b & 0xF);
  }

  if (i == buf_len && hex[i * 2] != '\0') {
    return ERROR_WRONG_HEX_ENCODING;
  }
  return i;
}

int secure_atoi(const char* s, int* result)
{
  char *end = NULL;
  errno = 0;
  long temp = strtol(s, &end, 10);
  if (end != s && errno != ERANGE && temp >= INT_MIN && temp <= INT_MAX) {
    *result = (int) temp;
    return 1;
  }
  return 0;
}

#define CHECK_LEN(x) if ((x) <= 0) { return x; }

#define TX_BUFFER_SIZE 1024 * 1024
#define TEMP_BUFFER_SIZE 256

void update_h256(blake2b_state *ctx, ns(H256_struct_t) h256)
{
  uint8_t buf[32];

  if (!h256) {
    return;
  }

  buf[0] = ns(H256_u0(h256));
  buf[1] = ns(H256_u1(h256));
  buf[2] = ns(H256_u2(h256));
  buf[3] = ns(H256_u3(h256));
  buf[4] = ns(H256_u4(h256));
  buf[5] = ns(H256_u5(h256));
  buf[6] = ns(H256_u6(h256));
  buf[7] = ns(H256_u7(h256));
  buf[8] = ns(H256_u8(h256));
  buf[9] = ns(H256_u9(h256));
  buf[10] = ns(H256_u10(h256));
  buf[11] = ns(H256_u11(h256));
  buf[12] = ns(H256_u12(h256));
  buf[13] = ns(H256_u13(h256));
  buf[14] = ns(H256_u14(h256));
  buf[15] = ns(H256_u15(h256));
  buf[16] = ns(H256_u16(h256));
  buf[17] = ns(H256_u17(h256));
  buf[18] = ns(H256_u18(h256));
  buf[19] = ns(H256_u19(h256));
  buf[20] = ns(H256_u20(h256));
  buf[21] = ns(H256_u21(h256));
  buf[22] = ns(H256_u22(h256));
  buf[23] = ns(H256_u23(h256));
  buf[24] = ns(H256_u24(h256));
  buf[25] = ns(H256_u25(h256));
  buf[26] = ns(H256_u26(h256));
  buf[27] = ns(H256_u27(h256));
  buf[28] = ns(H256_u28(h256));
  buf[29] = ns(H256_u29(h256));
  buf[30] = ns(H256_u30(h256));
  buf[31] = ns(H256_u31(h256));
  blake2b_update(ctx, buf, 32);
}

void update_uint32_t(blake2b_state *ctx, uint32_t v)
{
  char buf[32];
  snprintf(buf, 32, "%d", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_uint64_t(blake2b_state *ctx, uint64_t v)
{
  char buf[32];
  snprintf(buf, 32, "%ld", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_out_point(blake2b_state *ctx, ns(OutPoint_table_t) outpoint)
{
  update_h256(ctx, ns(OutPoint_block_hash(outpoint)));
  update_h256(ctx, ns(OutPoint_tx_hash(outpoint)));
  update_uint32_t(ctx, ns(OutPoint_index(outpoint)));
}

void blake2b_hash(char * in_buf, int len, char * out_buf)
{
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, in_buf, len);
  blake2b_final(&blake2b_ctx, out_buf, BLAKE2B_BLOCK_SIZE);
}

char int_to_char(unsigned char i)
{
  if (i >= 0 && i <= 9) {
    return i + '0';
  }
  if (i >= 0xa && i <= 0xf) {
    return i + 'a' - 10;
  }
  return ERROR_WRONG_HEX_ENCODING;
}

int bin_to_hex(char* buf, size_t buf_len, const char* bin)
{
  volatile int i = 0;

  for (; i < (buf_len - 1) / 2; i++) {
    int tmp = bin[i];
    buf[2 * i] = int_to_char((unsigned char)((tmp & 0xf0) >> 4));
    buf[2 * i + 1] = int_to_char((unsigned char)(tmp & 0x0f));
  }

  buf[2 * i] = '\0';
  return 0;
}

int verify_sighash_all(const unsigned char* binary_pubkey_hash,
                       const unsigned char* binary_pubkey,
                       const unsigned char* binary_signature,
                       size_t signature_size)
{
  unsigned char hash[BLAKE2B_BLOCK_SIZE];
  int ret;

  /* Check pubkey hash */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, binary_pubkey, PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  if (memcmp(binary_pubkey_hash, hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  secp256k1_context context;
  if (secp256k1_context_initialize(&context, SECP256K1_CONTEXT_VERIFY) == 0) {
    return ERROR_SECP_INITIALIZE;
  }

  secp256k1_pubkey pubkey;
  ret = secp256k1_ec_pubkey_parse(&context, &pubkey, binary_pubkey, PUBKEY_SIZE);
  if (ret == 0) {
    return ERROR_SECP_PARSE_PUBKEY;
  }

  secp256k1_ecdsa_signature signature;
  ret = secp256k1_ecdsa_signature_parse_der(&context, &signature, binary_signature, signature_size);
  if (ret == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  uint64_t size = BLAKE2B_BLOCK_SIZE;
  if (ckb_load_tx_hash(hash, &size, 0) != CKB_SUCCESS || size != BLAKE2B_BLOCK_SIZE) {
    return ERROR_LOAD_TX;
  }

  ret = secp256k1_ecdsa_verify(&context, &signature, hash, &pubkey);
  if (ret != 1) {
    return ERROR_SECP_VERIFICATION;
  }
  return 0;
}
#endif  /* CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160 */
