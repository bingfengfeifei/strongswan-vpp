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
 * @defgroup cng_dh cng_dh
 * @{ @ingroup cng
 */

#ifndef CNG_DH_H_
#define CNG_DH_H_

typedef struct cng_dh_t cng_dh_t;

#include <library.h>

/**
 * Diffie-Hellman implementation using Cryptography API: Next Generation.
 */
struct cng_dh_t {

	/**
	 * Implements diffie_hellman_t interface.
	 */
	diffie_hellman_t dh;
};

/**
 * Creates a new cng_dh_t object.
 *
 * @param group			Diffie Hellman group number to use
 * @return				cng_dh_t object, NULL if not supported
 */
cng_dh_t *cng_dh_create(diffie_hellman_group_t group);

/**
 * Creates a new cng_dh_t object for MODP_CUSTOM.
 *
 * @param group			MODP_CUSTOM
 * @param g				generator
 * @param p				prime
 * @return				cng_dh_t object, NULL if not supported
 */
cng_dh_t *cng_dh_create_custom(diffie_hellman_group_t group,
							   chunk_t g, chunk_t p);

/**
 * Perform one-time initialization of DH algorithms
 */
void cng_dh_init();

/**
 * Perform deinitialization of   algorithms
 */
void cng_dh_deinit();

#endif /** CNG_DH_H_ @}*/
