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
 * @defgroup cng_hasher cng_hasher
 * @{ @ingroup cng
 */

#ifndef CNG_HASHER_H_
#define CNG_HASHER_H_

#include <crypto/hashers/hasher.h>

typedef struct cng_hasher_t cng_hasher_t;

/**
 * Hahser implementation using Cryptography API: Next Generation.
 */
struct cng_hasher_t {

	/**
	 * Implements hasher_t interface.
	 */
	hasher_t hasher;
};

/**
 * Create a cng_hasher instance.

 * @param algo			algorithm
 * @return				cng_hasher_t, NULL if not supported
 */
cng_hasher_t *cng_hasher_create(hash_algorithm_t algo);

/**
 * Perform one-time initialization of hasher algorithms
 */
void cng_hasher_init();

/**
 * Perform deinitialization of hasher algorithms
 */
void cng_hasher_deinit();

#endif /** CNG_HASHER_H_ @}*/
