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

/**
 * Provides a QSKE implementation that does no real work to make the tests run
 * faster.
 *
 * @defgroup mock_qske mock_qske
 * @{ @ingroup test_utils_c
 */

#ifndef MOCK_QSKE_H_
#define MOCK_QSKE_H_

#include <crypto/qske_mechanism.h>

/**
 * Creates a qske_t object.
 *
 * @param mechanism		QSKE mechanism
 * @return				created object
 */
qske_t *mock_qske_create(qske_mechanism_t mechanism);

#endif /** MOCK_QSKE_H_ @}*/
