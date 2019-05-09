#include "script.h"

INIT_GLOBAL_BUF

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

/*
arg[0] is "verify"
arg[1] is "cafe" the output[lock][args] which output point by input[previous_output]
if the args include many arguments, they will be flattened here.
arg[2] is "beef" input[args]
same to 2.
arg[3] is witness[0] which is a pubkey
arg[4] is witness[1] which is a signature
 */
int main(int argc, char* argv[])
{
    int ret;

    if (argc == 4) {
        // voter want to modify the vote
        // arg[1] is voter
        // arg[2] pubkey
        // arg[3] signature
        ret = check_sighash_all(argv[2], argv[3]);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[1]) != BLAKE160_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }
        if (memcmp(g_buf, g_addr, BLAKE160_SIZE) == 0) {
            return CKB_SUCCESS;
        }
        return ERROR_NO_PERMISSION;
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

    if (argc != 2 + 2 * m) {
        return ERROR_COUNT_WITNESSES;
    }

    // verify multi signature
    int ok_count = 0;
    for (int i = 0; i < m; i++) {
        debug(argv[argc - (2 + 2 * (m - i - 1))]);
        debug(argv[argc - (1 + 2 * (m - i - 1))]);
        ret = check_sighash_all(argv[argc - (2 + 2 * (m - i - 1))], argv[argc - (1 + 2 * (m - i - 1))]);
        if ((ret == CKB_SUCCESS) && (memcmp(g_multi_sig_addr[i], g_addr, BLAKE160_SIZE) == 0)) {
            ok_count += 1;
        }
    }

    {
        char buf[32];
        memset(buf, 0, 32);
        snprintf(buf, 32, "m %d n %d ok %d", m, n, ok_count);
        debug(buf);
    }

    if (ok_count < n) {
        return ERROR_MULTI_VERIFICATION;
    }

    //check the summary
    int total = 0;
    int yes = 0;
    ns(Transaction_table_t) tx;
    if (!(tx = ns(Transaction_as_root(g_tx_buf)))) {
        return ERROR_PARSE_TX;
    }

    ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
    size_t inputs_len = ns(CellInput_vec_len(inputs));
    for (int i = 0; i < inputs_len; i++) {
        volatile uint64_t len = TEMP_BUFFER_SIZE;
        if (ckb_load_cell_by_field(g_buf, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
            return ERROR_LOAD_INPUT_DATA;
        }
        total++;
        if (len > 0) {
            yes++;
        }
    }

    {
        char buf[32];
        memset(buf, 0, 32);
        snprintf(buf, 32, "total %d yes %d", total, yes);
        debug(buf);
    }

    ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
    size_t outputs_len = ns(CellOutput_vec_len(outputs));
    if (outputs_len > 1) {
        return ERROR_TOO_MANY_OUTPUT;
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