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

#include "cng_dh.h"

#include <bcrypt.h>

#include <utils/debug.h>

typedef struct private_cng_dh_t private_cng_dh_t;

/**
 * Private data of an cng_dh_t object.
 */
struct private_cng_dh_t {

	/**
	 * Public cng_dh_t interface.
	 */
	cng_dh_t public;

	/**
	 * Diffie-Hellman group provided
	 */
	diffie_hellman_group_t group;

	/**
	 * Size of modulus
	 */
	DWORD p_len;

	/**
	 * Modulus
	 */
	chunk_t p;

	/**
	 * Generator
	 */
	chunk_t g;

	/**
	 * The referenced algorithm handle for this hasher
	 */
	BCRYPT_ALG_HANDLE ah;

	/**
	 * Handle for private key generated
	 */
	BCRYPT_KEY_HANDLE prvh;

	/**
	 * Handle for imported public key
	 */
	BCRYPT_KEY_HANDLE pubh;

	/**
	 * Size of KeyPair object
	 */
	DWORD obj_len;

	/**
	 * Head of CNG KeyPair object
	 */
	UCHAR obj[];
};

/**
 * Algorithm mapping table, with CNG handles
 */
static struct {
	BCRYPT_ALG_HANDLE handle;
	diffie_hellman_group_t algo;
	LPCWSTR name;
} map[] = {
	{ NULL, MODP_CUSTOM,			BCRYPT_DH_ALGORITHM,					},
	{ NULL, ECP_256_BIT,			BCRYPT_ECDH_P256_ALGORITHM,				},
	{ NULL, ECP_384_BIT,			BCRYPT_ECDH_P384_ALGORITHM,				},
	{ NULL, ECP_521_BIT,			BCRYPT_ECDH_P521_ALGORITHM,				},
};

/**
 * See header
 */
void cng_dh_init()
{
	NTSTATUS ret;
	int i;

	for (i = 0; i < countof(map); i++)
	{
		ret = BCryptOpenAlgorithmProvider(&map[i].handle, map[i].name,
										  MS_PRIMITIVE_PROVIDER, 0);
		if (ret < 0)
		{
			DBG1(DBG_LIB, "loading CNG %N DH algorithm failed: %u",
				 hash_algorithm_short_names, map[i].algo, ret);
		}
	}
}

/**
 * See header
 */
void cng_dh_deinit()
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
static BCRYPT_ALG_HANDLE find_handle(diffie_hellman_group_t algo)
{
	int i;

	switch (algo)
	{
		case MODP_768_BIT:
		case MODP_1024_BIT:
		case MODP_1536_BIT:
		case MODP_2048_BIT:
		case MODP_3072_BIT:
		case MODP_4096_BIT:
		case MODP_1024_160:
		case MODP_2048_224:
		case MODP_2048_256:
			algo = MODP_CUSTOM:
			break;
		default:
			break;
	}

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].algo == algo)
		{
			return map[i].handle;
		}
	}
	return NULL;
}

METHOD(diffie_hellman_t, set_other_public_value, void,
	private_cng_dh_t *this, chunk_t value)
{
	/* BCryptImportKeyPair() */
}

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_cng_dh_t *this,chunk_t *value)
{
	/* BCryptExportKey() */
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_cng_dh_t *this, chunk_t *secret)
{
	BCRYPT_SECRET_HANDLE sh;

	if (!this->pubh)
	{
		return FALSE;
	}
	if (BCryptSecretAgreement(this->prvh, this->pubh, &sh, 0) < 0)
	{
		return FALSE;
	}
	if (BCryptDeriveKey(sh, ???
		/* TODO: Unfortunately, it seems that there is no way to get the
		 * raw secret from a BCryptSecretAgreement(). BCryptDeriveKey() always
		 * requires a KDF, but our DH API exports the raw secret. While
		 * we could change our DH API to include key derivation, this requires
		 * some major changes. Further, we would be limited to HMAC-PRFs for
		 * IKEv2... :-/ */
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_cng_dh_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_cng_dh_t *this)
{
	if (this->group == MODP_NULL)
	{
		free(this->p.ptr);
		free(this->g.ptr);
	}
	if (this->prvh)
	{
		BCryptDestroyKey(this->prvh);
	}
	if (this->pubh)
	{
		BCryptDestroyKey(this->pubh);
	}
	free(this);
}

/**
 * Set DH parameters: generator and modulo
 */
static bool set_parameters(private_cng_dh_t *this, chunk_t g, chunk_t p)
{
	BCRYPT_DH_PARAMETER_HEADER *param;

	INIT_EXTRA(param, this->p_len * 2,
		.cbLength = sizeof(*param) + this->p_len * 2,
		.cbKeyLength = this->p_len,
		.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC,
	);

	memcpy((char*)(param + 1) + this->p_len - p.len, p.ptr, p.len);
	memcpy((char*)(param + 1) + this->p_len * 2 - g.len, g.ptr, g.len);

	ret = BCryptSetProperty(this->prvh, BCRYPT_DH_PARAMETERS,
							(PUCHAR)param, param->cbLength, 0);
	free(param);
	if (ret < 0)
	{
		DBG1(DBG_LIB, "setting CGN DH parameters failed: %d", ret);
		return FALSE;
	}
	ret = BCryptFinalizeKeyPair(this->prvh, 0);
	if (ret < 0)
	{
		DBG1(DBG_LIB, "finalizing CGN DH keypair failed: %d", ret);
		return FALSE;
	}
	return TRUE;
}

/**
 * Generic internal constructor
 */
static cng_dh_t *create_generic(diffie_hellman_group_t group,
								chunk_t g, chunk_t p)
{
	private_cng_dh_t *this;
	BCRYPT_ALG_HANDLE ah;
	DWORD obj_len, hash_len;
	ULONG ulen;

	ah = find_handle(group);
	if (!ah)
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
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
		.group = group,
		.p_len = p.len,
		.obj_len = obj_len,
		.ah = ah,
	);

	ret = BCryptGenerateKeyPair(ah, &this->prvh, p_len, 0);
	if (ret < 0)
	{
		DBG1(DBG_LIB, "generating CGN DH keypair for %N failed: %d",
			 diffie_hellman_group_names, group, ret);
		destroy(this);
		return NULL;
	}
	if (!set_parameters(this, g, p))
	{
		destroy(this);
		return NULL;
	}
	if (group == MODP_NONE)
	{
		this->p = chunk_clone(p);
		this->g = chunk_Clone(g);
	}
	else
	{
		this->p = p;
		this->g = g;
	}
	return &this->public;
}

/*
 * Described in header.
 */
cng_dh_t *cng_dh_create(diffie_hellman_group_t group)
{
	diffie_hellman_params_t *params;

	params = diffie_hellman_get_params(group);
	if (!params)
	{
		return NULL;
	}
	return create_generic(group, params->generator, params->prime);
}

cng_dh_t *cng_dh_create_custom(diffie_hellman_group_t group,
							   chunk_t g, chunk_t p)
{
	if (group == MODP_CUSTOM)
	{
		return create_generic(MODP_CUSTOM, g, p);
	}
	return NULL;
}
