/*
 * Copyright (C) 2016 Andreas Steffen
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

/**
 * @defgroup qske_newhope_noise qske_newhope_noise
 * @{ @ingroup qske_newhope_p
 */

#ifndef QSKE_NEWHOPE_NOISE_H_
#define QSKE_NEWHOPE_NOISE_H_

typedef struct qske_newhope_noise_t qske_newhope_noise_t;

#include <library.h>

/**
 * Generate pseudo random noise using a ChaCha20 stream
 * initialized with a 256 bit seed and an 8 bit nonce
 */
struct qske_newhope_noise_t {

	/**
	 * Return n pseudo random bytes with a uniform distribution
	 *
	 * @param nonce		Nonce determining the pseudo random stream
	 * @param n			Number of pseudo random bytes to be returned
	 * @return			Return array with n peudo random bytes
	 */
	uint8_t* (*get_uniform_bytes)(qske_newhope_noise_t *this, uint8_t nonce,
								  uint16_t n);

	/**
	 * Return n pseudo random 32-bit words with a Psi16 binomial distribution
	 *
	 * @param nonce		Nonce determining the pseudo random stream
	 * @param n			Number of pseudo random Psi16 words to be returned
	 * @param q			Prime number q determining the ring
	 * @return			Return array with n pseudo random 32 bit words
	 */
	uint32_t* (*get_binomial_words)(qske_newhope_noise_t *this, uint8_t nonce,
									uint16_t n, uint16_t q);

	/**
	 * Destroy a qske_newhope_noise_t object
	 */
	void (*destroy)(qske_newhope_noise_t *this);
};

/**
 * Creates a new qske_newhope_noise_t object.
 *
 * @param seed			256 bit seed (32 byte chunk)
 * @return				qske_newhope_noise_t object, NULL if not supported
 */
qske_newhope_noise_t *qske_newhope_noise_create(chunk_t seed);

#endif /** QSKE_NEWHOPE_NOISE_H_ @}*/

