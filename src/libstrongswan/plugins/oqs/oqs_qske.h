/*
 * Copyright (C) 2018 Andreas Steffen
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
 * @defgroup oqs_qske oqs_qske
 * @{ @ingroup oqs_p
 */

#ifndef OQS_QSKE_H_
#define OQS_QSKE_H_

typedef struct oqs_qske_t oqs_qske_t;

#include <library.h>

/**
 * Quantum-safe key encapsulation implementation using the OQS_QSKE library
 */
struct oqs_qske_t {

	/**
	 * Implements qske_t interface.
	 */
	qske_t qske;
};

/**
 * Creates a new oqs_qske_t object.
 *
 * @param mechanism		QSKE mechanism number
 * @return				oqs_qske_t object, NULL if not supported
 */
oqs_qske_t *oqs_qske_create(qske_mechanism_t mechanism);

#endif /** OQS_QSKE_H_ @}*/

