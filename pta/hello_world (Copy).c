/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Example PTA implementation for Lotto using Ed25519.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

/* Define your UUID and command IDs here.
 * Use your own UUID (here we use dc225b98-6162-414a-834f-a3ec9def365c).
 */
#define LOTTO_PTA_UUID \
	{ 0xdc225b98, 0x6162, 0x414a, { 0x83, 0x4f, 0xa3, 0xec, 0x9d, 0xef, 0x36, 0x5c } }

#define LOTTO_CMD_GENERATE_KEYS         0
#define LOTTO_CMD_GENERATE_RANDOMNESS   1
#define LOTTO_CMD_VERIFY_RANDOMNESS     2

/* Include the crypto libraries from orlp/ed25519 and related files.
 * Make sure these headers are in your include path.
 */
#include "ed25519.h"
#include "sha512.h"
#include "sc.h"
#include "ge.h"
#include "fe.h"

/* Global variables:
 * g_sk: 64-byte expanded private key (first 32 bytes: clamped seed, next 32 bytes: public key)
 * g_pk: 32-byte public key stored separately
 */
static uint8_t g_sk[64];
static uint8_t g_pk[32];
static bool g_sk_initialized = false;

/*
 * PTA Entry Points
 */

/* Called when the PTA instance is created (loaded) */
TEE_Result pta_lotto_create_entry_point(void)
{
	DMSG("Lotto PTA using Ed25519 has been created");
	return TEE_SUCCESS;
}

/* Called when the PTA instance is destroyed (unloaded) */
void pta_lotto_destroy_entry_point(void)
{
	DMSG("Lotto PTA DestroyEntryPoint called");
}

/* Called when a new session is opened to the PTA.
 * Sessions are optional; here we just verify that no parameters are passed.
 */
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

/* Called when a session is closed */
void pta_lotto_close_session(void *sess_ctx)
{
	(void)sess_ctx;
	DMSG("Lotto PTA: Close session");
}

/*
 * Command Implementations
 */

/* Generate Keys:
 * - Generates a key pair using ed25519_create_keypair.
 * - Stores the 64-byte private key in g_sk and the public key in g_pk.
 * - Returns the public key to the caller.
 */
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
	TEE_GenerateRandom(seed, sizeof(seed));

	unsigned char pk[32], sk[64];
	ed25519_create_keypair(pk, sk, seed);

	memcpy(g_sk, sk, sizeof(sk));
	memcpy(g_pk, pk, sizeof(pk));
	g_sk_initialized = true;

	if (params[0].memref.size < sizeof(pk))
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[0].memref.buffer, pk, sizeof(pk));
	params[0].memref.size = sizeof(pk);
	return TEE_SUCCESS;
}

/* Generate Randomness:
 * - Signs the input message with the stored key pair.
 * - Returns a 64-byte signature (as the proof) and
 *   a 32-byte randomness value computed by hashing the signature.
 */
static TEE_Result pta_cmd_generate_randomness(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,    /* message */
		TEE_PARAM_TYPE_MEMREF_OUTPUT,   /* randomness output (32 bytes) */
		TEE_PARAM_TYPE_MEMREF_OUTPUT,   /* proof output (64 bytes) */
		TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!g_sk_initialized)
		return TEE_ERROR_BAD_STATE;

	const unsigned char *msg = params[0].memref.buffer;
	size_t msg_len = params[0].memref.size;

	unsigned char signature[64];
	ed25519_sign(signature, msg, msg_len, g_pk, g_sk);

	if (params[2].memref.size < sizeof(signature))
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[2].memref.buffer, signature, sizeof(signature));
	params[2].memref.size = sizeof(signature);

	/* Compute randomness as SHA-512 hash of the signature,
	 * then take the first 32 bytes.
	 */
	unsigned char hash[64];
	sha512_context ctx;
	sha512_init(&ctx);
	sha512_update(&ctx, signature, sizeof(signature));
	sha512_final(&ctx, hash);

	if (params[1].memref.size < 32)
		return TEE_ERROR_SHORT_BUFFER;
	memcpy(params[1].memref.buffer, hash, 32);
	params[1].memref.size = 32;

	return TEE_SUCCESS;
}

/* Verify Randomness:
 * - Verifies that the provided signature is valid for the input message and public key.
 * - Recomputes the randomness by hashing the signature and compares it with the provided randomness.
 */
static TEE_Result pta_cmd_verify_randomness(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,   /* message */
		TEE_PARAM_TYPE_MEMREF_INPUT,   /* public key (32 bytes) */
		TEE_PARAM_TYPE_MEMREF_INPUT,   /* randomness (32 bytes) */
		TEE_PARAM_TYPE_MEMREF_INPUT);  /* proof (signature, 64 bytes) */
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

	if (ed25519_verify(sig, msg, msg_len, pubkey) == 0) {
		EMSG("Signature verification failed");
		return TEE_ERROR_GENERIC;
	}

	unsigned char hash[64];
	sha512_context ctx;
	sha512_init(&ctx);
	sha512_update(&ctx, sig, 64);
	sha512_final(&ctx, hash);

	if (memcmp(rand_in, hash, 32) != 0) {
		EMSG("Randomness hash mismatch");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/*
 * PTA Invoke Command Entry Point:
 * Dispatches commands based on the cmd_id.
 */
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

/* PTA Registration: Register this PTA with OP-TEE OS */
pseudo_ta_register(
	.uuid = LOTTO_PTA_UUID,
	.name = "lotto_pta",
	.flags = PTA_DEFAULT_FLAGS,
	.invoke_command_entry_point = pta_lotto_invoke_command_entry_point,
	.open_session_entry_point = pta_lotto_open_session,
	.close_session_entry_point = pta_lotto_close_session
);

