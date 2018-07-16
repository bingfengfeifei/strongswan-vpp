/*
 * Copyright (C) 2018 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "mock_qske.h"

typedef struct private_qske_t private_qske_t;

/**
 * Private data
 */
struct private_qske_t {

	/**
	 * Public interface
	 */
	qske_t public;

	/**
	 * Instantiated QSKE mechanism
	 */
	qske_mechanism_t mechanism;
};

METHOD(qske_t, get_qske_mechanism, qske_mechanism_t,
	private_qske_t *this)
{
	return this->mechanism;
}

METHOD(qske_t, get_public_key, bool,
	private_qske_t *this, chunk_t *value)
{
	*value = chunk_empty;
	return TRUE;
}

METHOD(qske_t, set_public_key, bool,
	private_qske_t *this, chunk_t value)
{
	return TRUE;
}

METHOD(qske_t, get_ciphertext, bool,
	private_qske_t *this, chunk_t *value)
{
	*value = chunk_empty;
	return TRUE;
}

METHOD(qske_t, set_ciphertext, bool,
	private_qske_t *this, chunk_t value)
{
	return TRUE;
}

METHOD(qske_t, get_shared_secret, bool,
	private_qske_t *this, chunk_t *secret)
{
	*secret = chunk_clone(chunk_from_chars(0x01, 0x02, 0x03, 0x04));
	return TRUE;
}

METHOD(qske_t, set_nist_drbg_mode, bool,
	private_qske_t *this, bool enable, chunk_t seed)
{
	return TRUE;
}

METHOD(qske_t, destroy, void,
	private_qske_t *this)
{
	free(this);
}

/**
 * See header
 */
qske_t *mock_qske_create(qske_mechanism_t mechanism)
{
	private_qske_t *this;

	INIT(this,
		.public = {
			.get_qske_mechanism = _get_qske_mechanism,
			.get_public_key = _get_public_key,
			.set_public_key = _set_public_key,
			.get_ciphertext = _get_ciphertext,
			.set_ciphertext = _set_ciphertext,
			.get_shared_secret = _get_shared_secret,
			.set_nist_drbg_mode = _set_nist_drbg_mode,
			.destroy = _destroy,
		},
		.mechanism = mechanism,
	);
	return &this->public;
}
