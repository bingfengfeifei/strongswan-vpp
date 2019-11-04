/*
 * Copyright (C) 2019 Sean Parkinson, wolfSSL Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "wolfssl_common.h"

#ifdef HAVE_CURVE25519

#include "wolfssl_x_diffie_hellman.h"

#include <utils/debug.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/fe_operations.h>

typedef struct private_diffie_hellman_t private_diffie_hellman_t;

/**
 * Private data
 */
struct private_diffie_hellman_t {

	/**
	 * Public interface.
	 */
	key_exchange_t public;

	/**
	 * Diffie Hellman group number.
	 */
	key_exchange_method_t group;

	/**
	 * Private (public) key
	 */
	curve25519_key key;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;
};

/**
 * Compute the shared secret
 */
static bool compute_shared_key(private_diffie_hellman_t *this,
							   curve25519_key *pub, chunk_t *shared_secret)
{
	word32 len = CURVE25519_KEYSIZE;
	int ret;

	*shared_secret = chunk_alloc(len);
	ret = wc_curve25519_shared_secret_ex(&this->key, pub, shared_secret->ptr,
										 &len, EC25519_LITTLE_ENDIAN);
	return ret == 0;
}

METHOD(key_exchange_t, set_public_key, bool,
	private_diffie_hellman_t *this, chunk_t value)
{
	curve25519_key pub;
	int ret;

	if (!key_exchange_verify_pubkey(this->group, value))
	{
		return FALSE;
	}

	ret = wc_curve25519_init(&pub);
	if (ret != 0)
	{
		DBG1(DBG_LIB, "%N public key initialization failed",
			 key_exchange_method_names, this->group);
		return FALSE;
	}

	ret = wc_curve25519_import_public_ex(value.ptr, value.len, &pub,
										 EC25519_LITTLE_ENDIAN);
	if (ret != 0)
	{
		DBG1(DBG_LIB, "%N public value is malformed",
			 key_exchange_method_names, this->group);
		return FALSE;
	}

	chunk_clear(&this->shared_secret);

	if (!compute_shared_key(this, &pub, &this->shared_secret))
	{
		DBG1(DBG_LIB, "%N shared secret computation failed",
			 key_exchange_method_names, this->group);
		chunk_clear(&this->shared_secret);
		wc_curve25519_free(&pub);
		return FALSE;
	}
	wc_curve25519_free(&pub);
	return TRUE;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_diffie_hellman_t *this, chunk_t *value)
{
	word32 len = CURVE25519_KEYSIZE;

	*value = chunk_alloc(len);
	if (wc_curve25519_export_public_ex(&this->key, value->ptr, &len,
									   EC25519_LITTLE_ENDIAN) != 0)
	{
		chunk_free(value);
		return FALSE;
	}
	return TRUE;
}

METHOD(key_exchange_t, set_seed, bool,
	private_diffie_hellman_t *this, chunk_t value, drbg_t *drbg)
{
	curve25519_key pub;
	u_char basepoint[CURVE25519_KEYSIZE] = {9};
	word32 len = CURVE25519_KEYSIZE;
	int ret;

	ret = wc_curve25519_init(&pub);
	/* create base point for calculating public key */
	if (ret == 0)
	{
		ret = wc_curve25519_import_public_ex(basepoint, CURVE25519_KEYSIZE,
											 &pub, EC25519_LITTLE_ENDIAN);
	}
	if (ret == 0)
	{
		ret = wc_curve25519_import_private_ex(value.ptr, value.len, &this->key,
											  EC25519_LITTLE_ENDIAN);
	}
	if (ret == 0)
	{
		ret = wc_curve25519_shared_secret_ex(&this->key, &pub,
								this->key.p.point, &len, EC25519_LITTLE_ENDIAN);
	}
	return ret == 0;
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_diffie_hellman_t *this, chunk_t *secret)
{
	if (!this->shared_secret.len)
	{
		return FALSE;
	}
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(key_exchange_t, destroy, void,
	private_diffie_hellman_t *this)
{
	wc_curve25519_free(&this->key);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header
 */
key_exchange_t *wolfssl_x_diffie_hellman_create(key_exchange_method_t group)
{
	private_diffie_hellman_t *this;
	WC_RNG rng;
	int ret;

	INIT(this,
		.public = {
			.get_shared_secret = _get_shared_secret,
			.set_public_key = _set_public_key,
			.get_public_key = _get_public_key,
			.set_seed = _set_seed,
			.get_method = _get_method,
			.destroy = _destroy,
		},
		.group = group,
	);

	if (wc_curve25519_init(&this->key) != 0)
	{
		DBG1(DBG_LIB, "initializing key failed");
		free(this);
		return NULL;
	}

	if (wc_InitRng(&rng) != 0)
	{
		DBG1(DBG_LIB, "initializing a random number generator failed");
		destroy(this);
		return NULL;
	}
	ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &this->key);
	wc_FreeRng(&rng);
	if (ret != 0)
	{
		DBG1(DBG_LIB, "making a key failed");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* HAVE_CURVE25519 */
