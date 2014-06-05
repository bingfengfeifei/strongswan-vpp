/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "cng_hasher.h"

#include <bcrypt.h>

typedef struct private_cng_hasher_t private_cng_hasher_t;

/**
 * Private data of cng_hasher_t
 */
struct private_cng_hasher_t {

	/**
	 * Public part of this class.
	 */
	cng_hasher_t public;

	/**
	 * The referenced algorithm handle for this hasher
	 */
	BCRYPT_ALG_HANDLE ah;

	/**
	 * The owned hasher handle for this hasher
	 */
	BCRYPT_HASH_HANDLE hh;

	/**
	 * Hash size, in bytes
	 */
	DWORD hash_len;

	/**
	 * Size of hash object
	 */
	DWORD obj_len;

	/**
	 * Head of CNG hasher object
	 */
	UCHAR obj[];
};

/**
 * Algorithm mapping table, with CNG handles
 */
static struct {
	BCRYPT_ALG_HANDLE handle;
	hash_algorithm_t algo;
	LPCWSTR name;
} map[] = {
	{ NULL, HASH_MD2,				BCRYPT_MD2_ALGORITHM					},
	{ NULL, HASH_MD4,				BCRYPT_MD4_ALGORITHM					},
	{ NULL, HASH_MD5,				BCRYPT_MD5_ALGORITHM					},
	{ NULL, HASH_SHA1,				BCRYPT_SHA1_ALGORITHM					},
	{ NULL, HASH_SHA256,			BCRYPT_SHA256_ALGORITHM					},
	{ NULL, HASH_SHA384,			BCRYPT_SHA384_ALGORITHM					},
	{ NULL, HASH_SHA512,			BCRYPT_SHA512_ALGORITHM					},
};

/**
 * See header
 */
void cng_hasher_init()
{
	NTSTATUS ret;
	int i;

	for (i = 0; i < countof(map); i++)
	{
		ret = BCryptOpenAlgorithmProvider(&map[i].handle, map[i].name,
										  MS_PRIMITIVE_PROVIDER, 0);
		if (ret < 0)
		{
			DBG1(DBG_LIB, "loading CNG %N hash algorithm failed: %u",
				 hash_algorithm_short_names, map[i].algo, ret);
		}
	}
}

/**
 * See header
 */
void cng_hasher_deinit()
{
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].handle)
		{
			BCryptCloseAlgorithmProvider(map[i].handle, 0);
		}
	}
}

/**
 * Find an existing handle for the given hash algorithm
 */
static BCRYPT_ALG_HANDLE find_handle(hash_algorithm_t algo)
{
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].algo == algo)
		{
			return map[i].handle;
		}
	}
	return NULL;
}

METHOD(hasher_t, get_hash_size, size_t,
	private_cng_hasher_t *this)
{
	return this->hash_len;
}

METHOD(hasher_t, reset, bool,
	private_cng_hasher_t *this)
{
	if (BCryptDestroyHash(this->hh) < 0)
	{
		return FALSE;
	}
	if (BCryptCreateHash(this->ah, &this->hh, this->obj, this->obj_len,
						 NULL, 0, 0) < 0)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(hasher_t, get_hash, bool,
	private_cng_hasher_t *this, chunk_t chunk, u_int8_t *hash)
{
	if (BCryptHashData(this->hh, chunk.ptr, chunk.len, 0) < 0)
	{
		return FALSE;
	}
	if (hash)
	{
		if (BCryptFinishHash(this->hh, hash, this->hash_len, 0) < 0)
		{
			return FALSE;
		}
		/* reusable hashers are not supported before Windows 8, so we must
		 * BCryptDestroyHash() after BCryptFinishHash(). */
		return reset(this);
	}
	return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
	private_cng_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
	if (hash)
	{
		*hash = chunk_alloc(this->hash_len);
		return get_hash(this, chunk, hash->ptr);
	}
	return get_hash(this, chunk, NULL);
}

METHOD(hasher_t, destroy, void,
	private_cng_hasher_t *this)
{
	BCryptDestroyHash(this->hh);
	free(this);
}

/*
 * Described in header
 */
cng_hasher_t *cng_hasher_create(hash_algorithm_t algo)
{
	private_cng_hasher_t *this;
	BCRYPT_ALG_HANDLE ah;
	DWORD obj_len, hash_len;
	ULONG ulen;

	ah = find_handle(algo);
	if (!ah)
	{
		return NULL;
	}
	if (BCryptGetProperty(ah, BCRYPT_OBJECT_LENGTH,
						  (PUCHAR)&obj_len, sizeof(obj_len), &ulen, 0) < 0)
	{
		return NULL;
	}
	if (BCryptGetProperty(ah, BCRYPT_HASH_LENGTH,
						  (PUCHAR)&hash_len, sizeof(hash_len), &ulen, 0) < 0)
	{
		return NULL;
	}

	INIT_EXTRA(this, obj_len,
		.public = {
			.hasher = {
				.get_hash = _get_hash,
				.allocate_hash = _allocate_hash,
				.get_hash_size = _get_hash_size,
				.reset = _reset,
				.destroy = _destroy,
			},
		},
		.ah = ah,
		.hash_len = hash_len,
		.obj_len = obj_len,
	);

	if (BCryptCreateHash(this->ah, &this->hh, this->obj, this->obj_len,
						 NULL, 0, 0) < 0)
	{
		free(this);
		return NULL;
	}
	return &this->public;
}
