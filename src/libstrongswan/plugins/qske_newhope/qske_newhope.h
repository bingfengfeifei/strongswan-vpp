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
 * @defgroup qske_newhope qske_newhope
 * @{ @ingroup newhope_p
 */

#ifndef QSKE_NEWHOPE_H_
#define QSKE_NEWHOPE_H_

typedef struct qske_newhope_t qske_newhope_t;

#include <library.h>

/**
 * Quantum-safe key encapsulation implementation using the NewHope mechanism
 */
struct qske_newhope_t {

	/**
	 * Implements qske_t interface.
	 */
	qske_t qske;
};

/**
 * Creates a new qske_newhope_t object.
 *
 * @param mechanism		QSKE mechanism number
 * @return				qske_newhope_t object, NULL if not supported
 */
qske_newhope_t *qske_newhope_create(qske_mechanism_t mechanism);

#endif /** QSKE_NEWHOPE_H_ @}*/

