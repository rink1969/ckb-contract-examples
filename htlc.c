#include "script.h"

char g_buf[TEMP_SIZE];

// error code
#define ERROR_ARG_COUNT -60
#define ERROR_ONLY_RECEIVER_UNLOCK -61
#define ERROR_LOCK_HASH_LEN -62
#define ERROR_LOCK_HASH_IMAGE -63
#define ERROR_SENDER -64
#define ERROR_RECEIVER -65
#define ERROR_HASH_LEN -66
#define ERROR_LOAD_OUTPUT_DATA -67

int main(int argc, char* argv[])
{
    int ret, len;
    uint64_t length = 0;
    int flag = 0;

    // if have data and data is hash, it's unlock
    // or else is exit
    {
        volatile uint64_t len = TEMP_SIZE;
        if ((ckb_load_cell_by_field(g_buf, &len, 0, 0, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA) == CKB_SUCCESS) && (len == 32)) {
          flag = 1;
        }
    }

    if (flag == 1) {
        // unlock
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash  32bytes

        // only receiver can unlock
        ret = verify_sighash_all(argv[2], 0);
        if (ret != CKB_SUCCESS) {
            return ret;
        }

        {
            volatile uint64_t len = TEMP_SIZE;
            if (ckb_load_cell_by_field(g_buf, &len, 0, 0, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
              return ERROR_LOAD_OUTPUT_DATA;
            }
            if (len != 32) {
              return ERROR_HASH_LEN;
            }
        }

        char hash[BLAKE2B_BLOCK_SIZE];
        blake2b_hash(g_buf, BLAKE2B_BLOCK_SIZE, hash);

        if (memcmp(hash, argv[3], BLAKE2B_BLOCK_SIZE) != 0) {
            return ERROR_LOCK_HASH_IMAGE;
        }
    } else {
        // exit
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash

        ret = verify_sighash_all(argv[1], 0);
        if (ret != CKB_SUCCESS) {
            return ERROR_SENDER;
        }
        ret = verify_sighash_all(argv[2], 1);
        if (ret != CKB_SUCCESS) {
            return ERROR_RECEIVER;
        }
    }
    return CKB_SUCCESS;
}