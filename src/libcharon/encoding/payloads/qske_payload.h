/*
 * Copyright (C) 2018 Tobias Brunner
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
 * @defgroup qske_payload qske_payload
 * @{ @ingroup payloads
 */

#ifndef QSKE_PAYLOAD_H_
#define QSKE_PAYLOAD_H_

typedef struct qske_payload_t qske_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <crypto/qske_mechanism.h>

/**
 * Class representing an IKEv2 quantum-save key exchange payload.
 */
struct qske_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Returns the Quantum-Safe Key Exchange data of this QSKE payload.
	 *
	 * @return 			chunk_t pointing to internal data
	 */
	chunk_t (*get_qske_data) (qske_payload_t *this);

	/**
	 * Gets the QSKE mmechanism number of this QSKE payload.
	 *
	 * @return 			QSKE mechanism number of this payload
	 */
	qske_mechanism_t (*get_qske_mechanism) (qske_payload_t *this);

	/**
	 * Destroys a qske_payload_t object.
	 */
	void (*destroy) (qske_payload_t *this);
};

/**
 * Creates an empty qske_payload_t object.
 *
  * @return				qske_payload_t object
 */
qske_payload_t *qske_payload_create(void);

/**
 * Creates a qske_payload_t from a qske_t.
 *
 * @param qske			QSKE object containing mechanism and key
 * @param initiator 	TRUE if initiator, FALSE as responder
 * @return 				qske_payload_t object, NULL on error
 */
qske_payload_t *qske_payload_create_from_qske(qske_t *qske, bool initiator);

#endif /** QSKE_PAYLOAD_H_ @}*/
