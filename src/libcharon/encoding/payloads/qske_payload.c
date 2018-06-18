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

#include <stddef.h>

#include "qske_payload.h"

#include <encoding/payloads/encodings.h>

typedef struct private_qske_payload_t private_qske_payload_t;

/**
 * Private data of an qske_payload_t object.
 */
struct private_qske_payload_t {

	/**
	 * Public qske_payload_t interface.
	 */
	qske_payload_t public;

	/**
	 * Next payload type.
	 */
	uint8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;

	/**
	 * Reserved bits
	 */
	bool reserved_bit[7];

	/**
	 * Reserved bytes
	 */
	uint8_t reserved_byte[2];

	/**
	 * Length of this payload.
	 */
	uint16_t payload_length;

	/**
	 * QSKE mechanism nuber
	 */
	uint16_t qske_mechanism;

	/**
	 * Quantum-Safe Key Exchange Data of this QSKE payload.
	 */
	chunk_t qske_data;
};

/**
 * Encoding rules for IKEv2 quantum-save key exchange payload.
 */
static encoding_rule_t encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,				offsetof(private_qske_payload_t, next_payload)     },
	/* the critical bit */
	{ FLAG,					offsetof(private_qske_payload_t, critical)         },
	/* 7 Bit reserved bits */
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[0])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[1])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[2])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[3])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[4])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[5])  },
	{ RESERVED_BIT,			offsetof(private_qske_payload_t, reserved_bit[6])  },
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,		offsetof(private_qske_payload_t, payload_length)   },
	/* QSKE mechanism number as 16 bit field*/
	{ U_INT_16,				offsetof(private_qske_payload_t, qske_mechanism)   },
	/* 2 reserved bytes */
	{ RESERVED_BYTE,		offsetof(private_qske_payload_t, reserved_byte[0]) },
	{ RESERVED_BYTE,		offsetof(private_qske_payload_t, reserved_byte[1]) },
	/* Quantum-Safe Key Exchange Data is from variable size */
	{ CHUNK_DATA,			offsetof(private_qske_payload_t, qske_data)        },
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !        QSKE Mechanism #       !           RESERVED            !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                Quantum-Safe Key Exchange Data                 ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


METHOD(payload_t, verify, status_t,
	private_qske_payload_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, int,
	private_qske_payload_t *this, encoding_rule_t **rules)
{
	*rules = encodings;
	return countof(encodings);
}

METHOD(payload_t, get_header_length, int,
	private_qske_payload_t *this)
{
	return 8;
}

METHOD(payload_t, get_type, payload_type_t,
	private_qske_payload_t *this)
{
	return PLV2_QSKE;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_qske_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_qske_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

METHOD(payload_t, get_length, size_t,
	private_qske_payload_t *this)
{
	return this->payload_length;
}

METHOD(qske_payload_t, get_qske_data, chunk_t,
	private_qske_payload_t *this)
{
	return this->qske_data;
}

METHOD(qske_payload_t, get_qske_mechanism, qske_mechanism_t,
	private_qske_payload_t *this)
{
	return this->qske_mechanism;
}

METHOD2(payload_t, qske_payload_t, destroy, void,
	private_qske_payload_t *this)
{
	free(this->qske_data.ptr);
	free(this);
}

/*
 * Described in header
 */
qske_payload_t *qske_payload_create(void)
{
	private_qske_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_header_length = _get_header_length,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.get_qske_data = _get_qske_data,
			.get_qske_mechanism = _get_qske_mechanism,
			.destroy = _destroy,
		},
		.next_payload = PL_NONE,
		.qske_mechanism = QSKE_NONE,
	);
	this->payload_length = get_header_length(this);
	return &this->public;
}

/*
 * Described in header
 */
qske_payload_t *qske_payload_create_from_qske(qske_t *qske, bool initiator)
{
	private_qske_payload_t *this;
	chunk_t value;

	if (initiator)
	{
		if (!qske->get_public_key(qske, &value))
		{
			return NULL;
		}
	}
	else
	{
		if (!qske->get_ciphertext(qske, &value))
		{
			return NULL;
		}
	}

	this = (private_qske_payload_t*)qske_payload_create();
	this->qske_data = value;
	this->qske_mechanism = qske->get_qske_mechanism(qske);
	this->payload_length += this->qske_data.len;

	return &this->public;
}
