#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <crypto/crypto.h>
#include <string.h>
#include <kernel/pseudo_ta.h>

#define LOTTO_PTA_UUID \
	{ 0xdc225b98, 0x6162, 0x414a, { 0x83, 0x4f, 0xa3, 0xec, 0x9d, 0xef, 0x36, 0x5c } }

#define LOTTO_CMD_GENERATE_KEYS         0
#define LOTTO_CMD_GENERATE_RANDOMNESS   1
#define LOTTO_CMD_VERIFY_RANDOMNESS     2

#include "ed25519.h"
#include "simple_sha512.h"
#include "simple_sc.h"
#include "simple_ge.h"
#include "simple_fe.h"

static uint8_t g_sk[64];
static uint8_t g_pk[32];
static bool g_sk_initialized = false;

TEE_Result pta_lotto_create_entry_point(void)
{
	DMSG("Lotto PTA using Ed25519 has been created");
	return TEE_SUCCESS;
}

void pta_lotto_destroy_entry_point(void)
{
	DMSG("Lotto PTA DestroyEntryPoint called");
}

TEE_Result pta_lotto_open_session(uint32_t param_types,
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

void pta_lotto_close_session(void *sess_ctx)
{
	(void)sess_ctx;
	DMSG("Lotto PTA: Close session");
}


static TEE_Result pta_cmd_generate_keys(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,  /* public key output */
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	unsigned char seed[32];
	crypto_rng_read(seed, sizeof(seed));

	unsigned char pk[32], sk[64];
	sed25519_create_keypair(pk, sk, seed);

	memcpy(g_sk, sk, sizeof(sk));
	memcpy(g_pk, pk, sizeof(pk));
	g_sk_initialized = true;

	if (params[0].memref.size < sizeof(pk))
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[0].memref.buffer, pk, sizeof(pk));
	params[0].memref.size = sizeof(pk);
	return TEE_SUCCESS;
}


static TEE_Result pta_cmd_generate_randomness(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!g_sk_initialized)
		return TEE_ERROR_BAD_STATE;

	const unsigned char *msg = params[0].memref.buffer;
	size_t msg_len = params[0].memref.size;

	unsigned char signature[64];
	sed25519_sign(signature, msg, msg_len, g_pk, g_sk);

	if (params[2].memref.size < sizeof(signature))
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[2].memref.buffer, signature, sizeof(signature));
	params[2].memref.size = sizeof(signature);

	unsigned char hash[64];
	sha512_context ctx;
	ssha512_init(&ctx);
	sha512_update(&ctx, signature, sizeof(signature));
	sha512_final(&ctx, hash);

	if (params[1].memref.size < 32)
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[1].memref.buffer, hash, 32);
	params[1].memref.size = 32;

	return TEE_SUCCESS;
}


static TEE_Result pta_cmd_verify_randomness(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size != 32 ||
	    params[2].memref.size != 32 ||
	    params[3].memref.size != 64)
		return TEE_ERROR_BAD_PARAMETERS;

	const unsigned char *msg    = params[0].memref.buffer;
	size_t msg_len            = params[0].memref.size;
	const unsigned char *pubkey = params[1].memref.buffer;
	const unsigned char *rand_in = params[2].memref.buffer;
	const unsigned char *sig    = params[3].memref.buffer;

	if (sed25519_verify(sig, msg, msg_len, pubkey) == 0) {
		EMSG("Signature verification failed");
		return TEE_ERROR_GENERIC;
	}

	unsigned char hash[64];
	sha512_context ctx;
	ssha512_init(&ctx);
	sha512_update(&ctx, sig, 64);
	sha512_final(&ctx, hash);

	if (memcmp(rand_in, hash, 32) != 0) {
		EMSG("Randomness hash mismatch");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result pta_lotto_invoke_command_entry_point(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types,
			TEE_Param params[4])
{
	(void)sess_ctx;
	switch (cmd_id) {
	case LOTTO_CMD_GENERATE_KEYS:
		return pta_cmd_generate_keys(param_types, params);
	case LOTTO_CMD_GENERATE_RANDOMNESS:
		return pta_cmd_generate_randomness(param_types, params);
	case LOTTO_CMD_VERIFY_RANDOMNESS:
		return pta_cmd_verify_randomness(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(
	.uuid = LOTTO_PTA_UUID,
	.name = "lotto_pta",
	.flags = PTA_DEFAULT_FLAGS,
	.invoke_command_entry_point = pta_lotto_invoke_command_entry_point,
	.open_session_entry_point = pta_lotto_open_session,
	.close_session_entry_point = pta_lotto_close_session
);
