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

#include "cng_crypter.h"

#include <bcrypt.h>

typedef struct private_cng_crypter_t private_cng_crypter_t;

/**
 * Private data of cng_crypter_t
 */
struct private_cng_crypter_t {

	/**
	 * Public part of this class.
	 */
	cng_crypter_t public;

	/**
	 * The referenced algorithm handle for this crypter
	 */
	BCRYPT_ALG_HANDLE ah;

	/**
	 * The owned symmetricKey handle for this crypter
	 */
	BCRYPT_KEY_HANDLE kh;

	/**
	 * Key size, in bytes
	 */
	size_t key_len;

	/**
	 * Block size, in bytes
	 */
	size_t block_len;

	/**
	 * Size of symmetricKey object
	 */
	DWORD obj_len;

	/**
	 * Head of CNG symmetricKey object
	 */
	UCHAR obj[];
};

/**
 * Algorithm mapping table, with CNG handles
 */
static struct {
	BCRYPT_ALG_HANDLE handle;
	encryption_algorithm_t algo;
	LPCWSTR name;
} map[] = {
	{ NULL, ENCR_AES_CBC,			BCRYPT_AES_ALGORITHM					},
	{ NULL, ENCR_3DES,				BCRYPT_3DES_ALGORITHM					},
	{ NULL, ENCR_DES,				BCRYPT_DES_ALGORITHM					},
};

/**
 * See header
 */
void cng_crypter_init()
{
	NTSTATUS ret;
	int i;

	for (i = 0; i < countof(map); i++)
	{
		ret = BCryptOpenAlgorithmProvider(&map[i].handle, map[i].name,
										  MS_PRIMITIVE_PROVIDER, 0);
		if (ret < 0)
		{
			DBG1(DBG_LIB, "loading CNG %N encryption algorithm failed: %u",
				 encryption_algorithm_names, map[i].algo, ret);
		}
	}
}

/**
 * See header
 */
void cng_crypter_deinit()
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
 * Find an existing handle for the given encryption algorithm
 */
static BCRYPT_ALG_HANDLE find_handle(encryption_algorithm_t algo)
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

METHOD(crypter_t, decrypt, bool,
	private_cng_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	ULONG ulen;

	if (!this->kh)
	{
		return FALSE;
	}
	iv = chunk_clonea(iv);
	if (dst)
	{
		*dst = chunk_alloc(data.len);
	}
	else
	{	/* for inline encryption, CGN supports identical buffers */
		dst = &data;
	}
	if (BCryptDecrypt(this->kh, data.ptr, data.len, NULL, iv.ptr, iv.len,
					  dst->ptr, dst->len, &ulen, 0) < 0)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(crypter_t, encrypt, bool,
	private_cng_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *dst)
{
	ULONG ulen;

	if (!this->kh)
	{
		return FALSE;
	}
	iv = chunk_clonea(iv);
	if (dst)
	{
		*dst = chunk_alloc(data.len);
	}
	else
	{	/* for inline encryption, CGN supports identical buffers */
		dst = &data;
	}
	if (BCryptEncrypt(this->kh, data.ptr, data.len, NULL, iv.ptr, iv.len,
					  dst->ptr, dst->len, &ulen, 0) < 0)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_cng_crypter_t *this)
{
	return this->block_len;
}

METHOD(crypter_t, get_iv_size, size_t,
	private_cng_crypter_t *this)
{
	return this->block_len;
}

METHOD(crypter_t, get_key_size, size_t,
	private_cng_crypter_t *this)
{
	return this->key_len;
}

METHOD(crypter_t, set_key, bool,
	private_cng_crypter_t *this, chunk_t key)
{
	if (this->kh)
	{
		if (BCryptDestroyKey(this->kh) < 0)
		{
			return FALSE;
		}
		this->kh = NULL;
	}
	if (BCryptGenerateSymmetricKey(this->ah, &this->kh, this->obj,
								   this->obj_len, key.ptr, key.len, 0) < 0)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_cng_crypter_t *this)
{
	if (this->kh)
	{
		BCryptDestroyKey(this->kh);
	}
	free(this);
}

/**
 * Check if a key length is valid in given BCRYPT_KEY_LENGTHS_STRUCT
 */
static size_t check_key_size(size_t key_size, BCRYPT_KEY_LENGTHS_STRUCT *kls)
{
	/* BCRYPT_KEY_LENGTHS_STRUCT uses key lengths in bits, not in bytes
	 * as documented, so convert to bits for comparison */
	if (key_size == 0)
	{
		return kls->dwMinLength / BITS_PER_BYTE;
	}
	key_size *= BITS_PER_BYTE;
	if (key_size < kls->dwMinLength || key_size > kls->dwMaxLength)
	{
		return 0;
	}
	if (kls->dwIncrement)
	{
		if ((key_size - kls->dwMinLength) % kls->dwIncrement)
		{
			return 0;
		}
	}
	else
	{
		if (key_size != kls->dwMinLength && key_size != kls->dwMaxLength)
		{
			return 0;
		}
	}
	return key_size / BITS_PER_BYTE;
}

/*
 * Described in header
 */
cng_crypter_t *cng_crypter_create(encryption_algorithm_t algo, size_t key_size)
{
	private_cng_crypter_t *this;
	BCRYPT_ALG_HANDLE ah;
	BCRYPT_KEY_LENGTHS_STRUCT kls;
	DWORD obj_len, block_len;
	ULONG ulen;

	ah = find_handle(algo);
	if (!ah)
	{
		return NULL;
	}
	if (BCryptGetProperty(ah, BCRYPT_KEY_LENGTHS,
						  (PUCHAR)&kls, sizeof(kls), &ulen, 0) < 0)
	{
		return NULL;
	}
	key_size = check_key_size(key_size, &kls);
	if (!key_size)
	{
		DBG1(DBG_LIB, "%zd-bit %N key size not supported by CNG",
			 key_size, encryption_algorithm_names, algo);
		return NULL;
	}
	if (BCryptGetProperty(ah, BCRYPT_BLOCK_LENGTH,
						  (PUCHAR)&block_len, sizeof(block_len), &ulen, 0) < 0)
	{
		return NULL;
	}
	if (BCryptGetProperty(ah, BCRYPT_OBJECT_LENGTH,
						  (PUCHAR)&obj_len, sizeof(obj_len), &ulen, 0) < 0)
	{
		return NULL;
	}

	INIT_EXTRA(this, obj_len,
		.public = {
			.crypter = {
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			},
		},
		.ah = ah,
		.obj_len = obj_len,
		.key_len = key_size,
		.block_len = block_len,
	);

	return &this->public;
}
