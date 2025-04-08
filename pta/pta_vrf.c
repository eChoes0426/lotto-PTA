#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <crypto/crypto.h>
#include <string.h>
#include <kernel/pseudo_ta.h>

#define LOTTO_VRF_UUID \
    { 0x9e70e748, 0x8135, 0x459d, { 0x84, 0xde, 0x26, 0x09, 0xa9, 0x76, 0xe8, 0x37 } }

#define LOTTO_VRF_GENERATE_KEYS         0
#define LOTTO_VRF_GENERATE_RANDOMNESS   1
#define LOTTO_VRF_VERIFY_RANDOMNESS     2

#include "vrf.h"
#include "crypto_vrf.h"
#include "randombytes.h"

static uint8_t g_sk[64];
static uint8_t g_pk[32];
static bool g_sk_initialized = false;

TEE_Result vrf_lotto_create_entry_point(void)
{
    DMSG("Lotto PTA using VRF has been created");
    return TEE_SUCCESS;
}

void vrf_lotto_destroy_entry_point(void)
{
    DMSG("Lotto PTA DestroyEntryPoint called");
}

TEE_Result vrf_lotto_open_session(uint32_t param_types,
                                  TEE_Param params[4],
                                  void **sess_ctx)
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    DMSG("Lotto PTA: Open session");
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    (void)params;
    (void)sess_ctx;
    return TEE_SUCCESS;
}

void vrf_lotto_close_session(void *sess_ctx)
{
    (void)sess_ctx;
    DMSG("Lotto PTA: Close session");
}

static TEE_Result vrf_cmd_generate_keys(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);
        
    DMSG("vrf_cmd_generate_keys: Entered");

    unsigned char pk[32], sk[64];

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < 32)
        return TEE_ERROR_SHORT_BUFFER;
        
    DMSG("vrf_cmd_generate_keys: About to call crypto_vrf_keypair");
    if (crypto_vrf_keypair(pk, sk) != 0) {
        EMSG("VRF keypair generation failed");
        return TEE_ERROR_GENERIC;
    }
    DMSG("vrf_cmd_generate_keys: crypto_vrf_keypair succeeded");
    
    memcpy(g_sk, sk, sizeof(sk));
    memcpy(g_pk, pk, sizeof(pk));
    g_sk_initialized = true;

    memcpy(params[0].memref.buffer, pk, sizeof(pk));
    params[0].memref.size = sizeof(pk);
    DMSG("vrf_cmd_generate_keys: Completed successfully");
    return TEE_SUCCESS;
}

static TEE_Result vrf_cmd_generate_randomness(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE);
    DMSG("vrf_cmd_generate_randomness: Entered");
    /* Declare variables at top */
    const unsigned char *msg;
    size_t msg_len;
    unsigned char proof[80];
    unsigned char randomness[64];

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!g_sk_initialized)
        return TEE_ERROR_BAD_STATE;

    msg = params[0].memref.buffer;
    msg_len = params[0].memref.size;

    DMSG("vrf_cmd_generate_randomness: Generating proof");
    if (crypto_vrf_ietfdraft03_prove(proof, g_sk, msg, msg_len) != 0) {
        EMSG("VRF proof generation failed");
        return TEE_ERROR_GENERIC;
    }
    DMSG("vrf_cmd_generate_randomness: Proof generated");
    
    if (crypto_vrf_ietfdraft03_proof_to_hash(randomness, proof) != 0) {
        EMSG("VRF proof-to-hash failed");
        return TEE_ERROR_GENERIC;
    }

    DMSG("vrf_cmd_generate_randomness: Randomness derived");

    if (params[1].memref.size < sizeof(randomness))
        return TEE_ERROR_SHORT_BUFFER;
    memcpy(params[1].memref.buffer, randomness, sizeof(randomness));
    params[1].memref.size = sizeof(randomness);

    if (params[2].memref.size < sizeof(proof))
        return TEE_ERROR_SHORT_BUFFER;
    memcpy(params[2].memref.buffer, proof, sizeof(proof));
    params[2].memref.size = sizeof(proof);

    DMSG("vrf_cmd_generate_randomness: Completed successfully");
    return TEE_SUCCESS;
}

static TEE_Result vrf_cmd_verify_randomness(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT);

    DMSG("vrf_cmd_verify_randomness: Entered");
    /* Declare variables at top */
    const unsigned char *msg;
    size_t msg_len;
    const unsigned char *pubkey;
    const unsigned char *rand_in;
    const unsigned char *proof;
    unsigned char derived_randomness[64];

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size != 32 ||
        params[2].memref.size != 64 ||
        params[3].memref.size != 80)
        return TEE_ERROR_BAD_PARAMETERS;

    msg     = params[0].memref.buffer;
    msg_len = params[0].memref.size;
    pubkey  = params[1].memref.buffer;
    rand_in = params[2].memref.buffer;
    proof   = params[3].memref.buffer;

    DMSG("vrf_cmd_verify_randomness: Calling crypto_vrf_ietfdraft03_verify");
    if (crypto_vrf_ietfdraft03_verify(derived_randomness,
                                      pubkey,
                                      proof,
                                      msg,
                                      (unsigned long long)msg_len) != 0) {
        EMSG("VRF proof verification failed");
        return TEE_ERROR_GENERIC;
    }
    
    DMSG("vrf_cmd_verify_randomness: Verification succeeded");
    if (memcmp(rand_in, derived_randomness, 64) != 0) {
        EMSG("Randomness mismatch");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    DMSG("vrf_cmd_verify_randomness: Randomness match, Completed successfully");
    return TEE_SUCCESS;
}

TEE_Result vrf_lotto_invoke_command_entry_point(void *sess_ctx,
                                                uint32_t cmd_id,
                                                uint32_t param_types,
                                                TEE_Param params[4])
{
    (void)sess_ctx;
    switch (cmd_id) {
    case LOTTO_VRF_GENERATE_KEYS:
        return vrf_cmd_generate_keys(param_types, params);
    case LOTTO_VRF_GENERATE_RANDOMNESS:
        return vrf_cmd_generate_randomness(param_types, params);
    case LOTTO_VRF_VERIFY_RANDOMNESS:
        return vrf_cmd_verify_randomness(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

pseudo_ta_register(
    .uuid = LOTTO_VRF_UUID,
    .name = "lotto_vrf",
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = vrf_lotto_invoke_command_entry_point,
    .open_session_entry_point = vrf_lotto_open_session,
    .close_session_entry_point = vrf_lotto_close_session
);

