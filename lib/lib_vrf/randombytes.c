/*
Copyright (c) 2018 Amir Hossein Alikhah Mishamandani
Copyright (c) 2018 Algorand LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO, THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <crypto/crypto.h>       // for crypto_rng_read()
#include <tee_api_defines.h>     // or <tee_internal_api.h> if needed
#include "randombytes.h"
#include "common.h"

/* Undefine any conflicting macros */
#undef random

static const randombytes_implementation *implementation = NULL;

/*
 * A default implementation that uses OP-TEE core's crypto_rng_read()
 */
static const char *default_impl_name(void)
{
    return "default-optee-core";
}

static uint32_t default_random(void)
{
    uint32_t r = 0;
    /* Use OP-TEE core RNG */
    crypto_rng_read(&r, sizeof(r));
    return r;
}

static void default_randombytes_buf(void * const buf, const size_t size)
{
    crypto_rng_read(buf, size);
}

static const randombytes_implementation default_impl = {
    .implementation_name = default_impl_name,
    .random = default_random,
    .uniform = NULL,
    .buf = default_randombytes_buf,
    .close = NULL,
};

/* Initialize the implementation if needed */
static void randombytes_init_if_needed(void)
{
    if (implementation == NULL) {
        implementation = &default_impl;
    }
}

int randombytes_set_implementation(randombytes_implementation *impl)
{
    implementation = impl;
    return 0;
}

const char *randombytes_implementation_name(void)
{
    randombytes_init_if_needed();
    return implementation->implementation_name();
}

uint32_t randombytes_random(void)
{
    randombytes_init_if_needed();
    return implementation->random();
}

uint32_t randombytes_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    randombytes_init_if_needed();
    if (implementation->uniform != NULL) {
        return implementation->uniform(upper_bound);
    }
    if (upper_bound < 2) {
        return 0;
    }
    min = (1U + ~upper_bound) % upper_bound;
    do {
        r = randombytes_random();
    } while (r < min);
    return r % upper_bound;
}

void randombytes_buf(void * const buf, const size_t size)
{
    randombytes_init_if_needed();
    if (size > (size_t) 0U) {
        implementation->buf(buf, size);
    }
}

size_t randombytes_seedbytes(void)
{
    return randombytes_SEEDBYTES;
}

int randombytes_close(void)
{
    if (implementation != NULL && implementation->close != NULL) {
        return implementation->close();
    }
    return 0;
}

void randombytes(unsigned char * const buf, const unsigned long long buf_len)
{
    assert(buf_len <= SIZE_MAX);
    randombytes_buf(buf, (size_t) buf_len);
}

