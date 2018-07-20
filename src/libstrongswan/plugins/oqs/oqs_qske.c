/*
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Based on public domain code by Erdem Alkim, Léo Ducas, Thomas Pöppelmann,
 * and Peter Schwabe.
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

#include "oqs_qske.h"

#include <utils/debug.h>

#include <oqs/oqs.h>

typedef struct private_oqs_qske_t private_oqs_qske_t;

/**
 * Private data of an oqs_qske_t object.
 */
struct private_oqs_qske_t {

	/**
	 * Public oqs_qske_t interface.
	 */
	oqs_qske_t public;

	/**
	 * QSKE_MECHANISM;
	 */
	qske_mechanism_t qske_mechanism;

	/**
	 * Internal OQS_KEM object
	 */
	OQS_KEM *kem;

	/**
	 * Public Key
	 */
	uint8_t *public_key;

	/**
	 * Secret Key
	 */
	uint8_t *secret_key;

	/**
	 * Ciphertext
	 */
	uint8_t *ciphertext;

	/**
	 * Shared secret
	 */
	uint8_t *shared_secret;

};


METHOD(qske_t, get_public_key, bool,
	private_oqs_qske_t *this, chunk_t *value)
{
	OQS_STATUS rc;

	if (!this->public_key)
	{
		this->public_key = malloc(this->kem->length_public_key);
		this->secret_key = malloc(this->kem->length_secret_key);
		rc = OQS_KEM_keypair(this->kem, this->public_key, this->secret_key);
		if (rc != OQS_SUCCESS)
		{
			DBG1(DBG_LIB, "%N keypair generation failed",
				 qske_mechanism_names, this->qske_mechanism);
			return FALSE;
		}
	}
	*value = chunk_clone(chunk_create(this->public_key,
									  this->kem->length_public_key));
	return TRUE;
}

/**
 * Generate the shared secret and encrypt it with the configured public key
 */
static bool encaps_shared_secret(private_oqs_qske_t *this)
{
	OQS_STATUS rc;

	if (!this->public_key)
	{
		DBG1(DBG_LIB, "no public key available for %N encapsulation",
			 qske_mechanism_names, this->qske_mechanism);
		return FALSE;
	}
	this->ciphertext    = malloc(this->kem->length_ciphertext);
	this->shared_secret = malloc(this->kem->length_shared_secret);
	memset(this->shared_secret, 0x00, this->kem->length_shared_secret);
	rc = OQS_KEM_encaps(this->kem, this->ciphertext, this->shared_secret,
						this->public_key);
	if (rc != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "%N encapsulation failed",
			 qske_mechanism_names, this->qske_mechanism);
		return FALSE;
	}
	return TRUE;
}

METHOD(qske_t, get_ciphertext, bool,
	private_oqs_qske_t *this, chunk_t *value)
{
	if (!this->ciphertext && !encaps_shared_secret(this))
	{
		return FALSE;
	}
	*value = chunk_clone(chunk_create(this->ciphertext,
									  this->kem->length_ciphertext));
	return TRUE;
}

METHOD(qske_t, get_shared_secret, bool,
	private_oqs_qske_t *this, chunk_t *secret)
{
	if (!this->shared_secret && !encaps_shared_secret(this))
	{
		return FALSE;
	}
	*secret = chunk_clone(chunk_create(this->shared_secret,
									   this->kem->length_shared_secret));
	return TRUE;
}

METHOD(qske_t, set_public_key, bool,
	private_oqs_qske_t *this, chunk_t value)
{
	if (value.len != this->kem->length_public_key)
	{
		DBG1(DBG_LIB, "wrong %N public key size of %u bytes, %u bytes expected",
			 qske_mechanism_names, this->qske_mechanism, value.len,
			 this->kem->length_public_key);
		return FALSE;
	}
	if (!this->public_key)
	{
		this->public_key = malloc(this->kem->length_public_key);
	}
	memcpy(this->public_key, value.ptr, value.len);

	return TRUE;
}

METHOD(qske_t, set_ciphertext, bool,
	private_oqs_qske_t *this, chunk_t value)
{
	OQS_STATUS rc;

	if (!this->public_key)
	{
		DBG1(DBG_LIB, "no secret key available for %N decapsulation",
			 qske_mechanism_names, this->qske_mechanism);
		return FALSE;
	}

	if (value.len != this->kem->length_ciphertext)
	{
		DBG1(DBG_LIB, "wrong %N ciphertext size of %u bytes, %u bytes expected",
			 qske_mechanism_names, this->qske_mechanism, value.len,
			 this->kem->length_ciphertext);
		return FALSE;
	}

	if (!this->shared_secret)
	{
		this->shared_secret = malloc(this->kem->length_shared_secret);
	}

	rc = OQS_KEM_decaps(this->kem, this->shared_secret, value.ptr,
						this->secret_key);
	if (rc != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "%N decapsulation failed",
			 qske_mechanism_names, this->qske_mechanism);
		return FALSE;
	}

	return TRUE;
}

METHOD(qske_t, get_qske_mechanism, qske_mechanism_t,
	private_oqs_qske_t *this)
{
	return this->qske_mechanism;
}

METHOD(qske_t, set_nist_drbg_mode, bool,
	private_oqs_qske_t *this, bool enable, chunk_t seed)
{
	OQS_STATUS rc;

	if (enable)
	{
		if (seed.len < 48)
		{
			DBG1(DBG_LIB, "not enough entropy input for NIST DRBG");
			return FALSE;
		}

		rc = OQS_randombytes_switch_algorithm(OQS_RAND_alg_nist_kat);
		if (rc != OQS_SUCCESS)
		{
			return FALSE;
		}
		OQS_randombytes_nist_kat_init(seed.ptr, NULL, 256);
	}
	else
	{
		rc = OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl);
		if (rc != OQS_SUCCESS)
		{
			return FALSE;
		}
	}

	return TRUE;
}

METHOD(qske_t, destroy, void,
	private_oqs_qske_t *this)
{
	if (this->secret_key)
	{
		memwipe(this->secret_key, this->kem->length_secret_key);
		free(this->secret_key);
	}
	if (this->shared_secret)
	{
		memwipe(this->shared_secret, this->kem->length_shared_secret);
		free(this->shared_secret);
	}
	OQS_KEM_free(this->kem);
	free(this->public_key);
	free(this->ciphertext);
	free(this);
}

/*
 * Described in header.
 */
oqs_qske_t *oqs_qske_create(qske_mechanism_t mechanism)
{
	private_oqs_qske_t *this;
	char *kem_alg = NULL;
	OQS_KEM *kem;

	switch (mechanism)
	{
		case QSKE_NEWHOPE_L1:
			kem_alg = OQS_KEM_alg_newhope_512_cca_kem;
			break;
		case QSKE_NEWHOPE_L5:
			kem_alg = OQS_KEM_alg_newhope_1024_cca_kem;
			break;
		case QSKE_FRODO_AES_L1:
			kem_alg = OQS_KEM_alg_frodokem_640_aes;
			break;
		case QSKE_FRODO_AES_L3:
			kem_alg = OQS_KEM_alg_frodokem_976_aes;
			break;
		case QSKE_FRODO_SHAKE_L1:
			kem_alg = OQS_KEM_alg_frodokem_640_cshake;
			break;
		case QSKE_FRODO_SHAKE_L3:
			kem_alg = OQS_KEM_alg_frodokem_976_cshake;
			break;
		case QSKE_KYBER_L1:
			kem_alg = OQS_KEM_alg_kyber512;
			break;
		case QSKE_KYBER_L3:
			kem_alg = OQS_KEM_alg_kyber768;
			break;
		case QSKE_KYBER_L5:
			kem_alg = OQS_KEM_alg_kyber1024;
			break;
		case QSKE_BIKE1_L1:
			kem_alg = OQS_KEM_alg_bike1_l1;
			break;
		case QSKE_BIKE1_L3:
			kem_alg = OQS_KEM_alg_bike1_l3;
			break;
		case QSKE_BIKE1_L5:
			kem_alg = OQS_KEM_alg_bike1_l5;
			break;
		case QSKE_BIKE2_L1:
			kem_alg = OQS_KEM_alg_bike2_l1;
			break;
		case QSKE_BIKE2_L3:
			kem_alg = OQS_KEM_alg_bike2_l3;
			break;
		case QSKE_BIKE2_L5:
			kem_alg = OQS_KEM_alg_bike2_l5;
			break;
		case QSKE_BIKE3_L1:
			kem_alg = OQS_KEM_alg_bike3_l1;
			break;
		case QSKE_BIKE3_L3:
			kem_alg = OQS_KEM_alg_bike3_l3;
			break;
		case QSKE_BIKE3_L5:
			kem_alg = OQS_KEM_alg_bike3_l5;
			break;
		case QSKE_SIKE_L1:
			kem_alg = OQS_KEM_alg_sike_p503;
			break;
		case QSKE_SIKE_L3:
			kem_alg = OQS_KEM_alg_sike_p751;
			break;
		case QSKE_SABER_L1:
			kem_alg = OQS_KEM_alg_saber_light_saber_kem;
			break;
		case QSKE_SABER_L3:
			kem_alg = OQS_KEM_alg_saber_saber_kem;
			break;
		case QSKE_SABER_L5:
			kem_alg = OQS_KEM_alg_saber_fire_saber_kem;
			break;
		case QSKE_LIMA_2P_L3:
			kem_alg = OQS_KEM_alg_lima_2p_1024_cca_kem;
			break;
		case QSKE_LIMA_2P_L5:
			kem_alg = OQS_KEM_alg_lima_2p_2048_cca_kem;
			break;
		case QSKE_LIMA_SP_L1:
			kem_alg = OQS_KEM_alg_lima_sp_1018_cca_kem;
			break;
		case QSKE_LIMA_SP_L2:
			kem_alg = OQS_KEM_alg_lima_sp_1306_cca_kem;
			break;
		case QSKE_LIMA_SP_L3:
			kem_alg = OQS_KEM_alg_lima_sp_1822_cca_kem;
			break;
		case QSKE_LIMA_SP_L5:
			kem_alg = OQS_KEM_alg_lima_sp_2062_cca_kem;
			break;
		default:
			return NULL;
	}

	kem = OQS_KEM_new(kem_alg);
	if (!kem)
	{
		DBG1(DBG_LIB, "OQS KEM '%s' not available", kem_alg);
		return NULL;
	}

	INIT(this,
		.public = {
			.qske = {
				.get_qske_mechanism = _get_qske_mechanism,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_ciphertext = _get_ciphertext,
				.set_ciphertext = _set_ciphertext,
				.get_shared_secret = _get_shared_secret,
				.set_nist_drbg_mode = _set_nist_drbg_mode,
				.destroy = _destroy,
			},
		},
		.qske_mechanism = mechanism,
		.kem = kem,
	);

	return &this->public;
}
