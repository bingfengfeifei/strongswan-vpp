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
 * @defgroup qske_newhope_reconciliation qske_newhope_reconciliation
 * @{ @ingroup qske_newhope_p
 */

#ifndef QSKE_NEWHOPE_RECONCILIATION_H_
#define QSKE_NEWHOPE_RECONCILIATION_H_

typedef struct qske_newhope_reconciliation_t qske_newhope_reconciliation_t;

#include <library.h>

/**
 * Class assisting the error reconciliation
 * resulting in a key exchange error rate < 2^(-60)
 */
struct qske_newhope_reconciliation_t {

	/**
	 * Generate reconciliation polynomial
	 *
	 * @param v			polynomial v
	 * @param rbits		pseudo random bit array
	 * @return			return array with reconciliation polynomial
	 */
	uint8_t* (*help_reconcile)(qske_newhope_reconciliation_t *this,
							   uint32_t *v, uint8_t *rbits);

	/**
	 * Use reconciliation polynomial r to derive shared secret
	 *
	 * @param v			polynomial v or v'
	 * @param r			reconciliation polynomial r
	 * @return			Return shared secret
	 */
	chunk_t (*reconcile)(qske_newhope_reconciliation_t *this,
						uint32_t *v, uint8_t *r);

	/**
	 * Destroy a qske_newhope_reconciliation_t object
	 */
	void (*destroy)(qske_newhope_reconciliation_t *this);
};

/**
 * Creates a new qske_newhope_reconciliation_t object.
 *
 * @param n				array size
 * @param q				prime modulus
 * @return				qske_newhope_reconciliation_t object
 */
qske_newhope_reconciliation_t *qske_newhope_reconciliation_create(int n, int32_t q);

#endif /** QSKE_NEWHOPE_RECONCILIATION_H_ @}*/

