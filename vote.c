#include "secp256k1_blake160.h"

char g_buf[TEMP_BUFFER_SIZE];

#define MAX_MULTI_SIGNERS 8
char g_multi_sig_addr[MAX_MULTI_SIGNERS][BLAKE160_SIZE];

// error code
#define ERROR_MULTI_VERIFICATION -60
#define ERROR_TOO_MANY_OUTPUT -61
#define ERROR_SUMMARY_LEN -62
#define ERROR_SUMMARY -63
#define ERROR_TOO_MANY_SIGNERS -64
#define ERROR_LOAD_CONF_DATA -65
#define ERROR_NO_PERMISSION -66
#define ERROR_COUNT_WITNESSES -67
#define ERROR_INVALID_CONF_DATA -67
#define ERROR_LOAD_INPUT_DATA -68
#define ERROR_LOAD_OUTPUT_DATA -69

/*
arg[0] is "verify"
arg[1] is "cafe" the output[lock][args] which output point by input[previous_output]
if the args include many arguments, they will be flattened here.
arg[2] is "beef" input[args]
same to 2.
arg[3] is witness[0] which is a pubkey
arg[4] is witness[1] which is a signature
arg[5] is length of signature
 */
int main(int argc, char* argv[])
{
    int ret;
    uint64_t length = 0;

    if (argc == 5) {
        // voter want to modify the vote
        // arg[1] is voter
        // arg[2] pubkey
        // arg[3] signature
        // arg[4] length of signature

        length = *((uint64_t *) argv[4]);
        return verify_sighash_all(argv[1], argv[2], argv[3], length);
    }

    // read conf data which store in deps[1]
    {
        volatile uint64_t len = TEMP_BUFFER_SIZE;
        if (ckb_load_cell_by_field(g_buf, &len, 0, 1, CKB_SOURCE_DEP, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
            return ERROR_LOAD_CONF_DATA;
        }
        int count = g_buf[0];
        if (len != 2 + count * BLAKE160_SIZE) {
            return ERROR_INVALID_CONF_DATA;
        }
    }
    int m = g_buf[0];
    int n = g_buf[1];
    if (m > MAX_MULTI_SIGNERS) {
        return ERROR_TOO_MANY_SIGNERS;
    }
    for (int i = 0; i < m; i++) {
        memcpy(g_multi_sig_addr[i], &g_buf[2 + i * BLAKE160_SIZE], BLAKE160_SIZE);
    }

    if (argc != 2 + 3 * m) {
        return ERROR_COUNT_WITNESSES;
    }

    // verify multi signature
    int ok_count = 0;
    for (int i = 0; i < m; i++) {
        length = *((uint64_t *)argv[argc - (1 + 3 * (m - i - 1))]);
        ret = verify_sighash_all(g_multi_sig_addr[i], argv[argc - (3 + 3 * (m - i - 1))], argv[argc - (2 + 3 * (m - i - 1))], length);
        if (ret == CKB_SUCCESS) {
            ok_count += 1;
        }
    }

    {
        char buf[32];
        memset(buf, 0, 32);
        snprintf(buf, 32, "m %d n %d ok %d", m, n, ok_count);
        ckb_debug(buf);
    }

    if (ok_count < n) {
        return ERROR_MULTI_VERIFICATION;
    }

    //check the summary
    int total = 0;
    int yes = 0;
    int i = 0;

    while (1) {
        volatile uint64_t len = TEMP_BUFFER_SIZE;
        ret = ckb_load_cell_by_field(g_buf, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        total++;
        if (len > 0) {
            yes++;
        }
        i++;
    }

    {
        char buf[32];
        memset(buf, 0, 32);
        snprintf(buf, 32, "total %d yes %d", total, yes);
        ckb_debug(buf);
    }

    {
        volatile uint64_t len = TEMP_BUFFER_SIZE;
        if (ckb_load_cell_by_field(g_buf, &len, 0, 0, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
          return ERROR_LOAD_OUTPUT_DATA;
        }
        if (len != 2) {
          return ERROR_SUMMARY_LEN;
        }
    }
    int summary_total = g_buf[0];
    int summary_yes = g_buf[1];
    if ((summary_total != total) || (summary_yes != yes)) {
        return ERROR_SUMMARY;
    }

    return CKB_SUCCESS;
}