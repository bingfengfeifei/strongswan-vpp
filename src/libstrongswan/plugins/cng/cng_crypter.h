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

/**
 * @defgroup cng_crypter cng_crypter
 * @{ @ingroup cng
 */

#ifndef CNG_CRYPTER_H_
#define CNG_CRYPTER_H_

typedef struct cng_crypter_t cng_crypter_t;

#include <crypto/crypters/crypter.h>

/**
 * Crypter implementation using Cryptography API: Next Generation.
 */
struct cng_crypter_t {

	/**
	 * Implements crypter_t interface.
	 */
	crypter_t crypter;
};

/**
 * Constructor to create cng_crypter_t.
 *
 * @param algo			algorithm to implement
 * @param key_size		key size in bytes
 * @return				cng_crypter_t, NULL if not supported
 */
cng_crypter_t *cng_crypter_create(encryption_algorithm_t algo, size_t key_size);

/**
 * Perform one-time initialization of crypter algorithms
 */
void cng_crypter_init();

/**
 * Perform deinitialization of crypter algorithms
 */
void cng_crypter_deinit();

#endif /** CNG_CRYPTER_H_ @}*/
