/*
 * Copyright (C) 2018 Tobias Brunner
 * Copyright (C) 2018-2019 Andreas Steffen
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
 * @defgroup qske_mechanism qske_mechanism
 * @{ @ingroup crypto
 */

#ifndef QSKE_MECHANISM_H_
#define QSKE_MECHANISM_H_

typedef enum qske_mechanism_t qske_mechanism_t;
typedef struct qske_t qske_t;
typedef struct qske_params_t qske_params_t;

#include <library.h>

/**
 * Quantum-Safe Key Encapsulation Mechanism
 *
 * KEM Candidates from the NIST Post-Quantum Cryptograpy Round 1 Submissions
 */
enum qske_mechanism_t {
	QSKE_NONE            =  0,
	QSKE_NEWHOPE         =  1,
	QSKE_NEWHOPE_L1      =  2,
	QSKE_NEWHOPE_L5      =  3,
	QSKE_FRODO_AES_L1    =  4,
	QSKE_FRODO_AES_L3    =  5,
	QSKE_FRODO_AES_L5    =  6,
	QSKE_FRODO_SHAKE_L1  =  7,
	QSKE_FRODO_SHAKE_L3  =  8,
	QSKE_FRODO_SHAKE_L5  =  9,
	QSKE_KYBER_L1        = 10,
	QSKE_KYBER_L3        = 11,
	QSKE_KYBER_L5        = 12,
	QSKE_BIKE1_L1        = 13,
	QSKE_BIKE1_L3        = 14,
	QSKE_BIKE1_L5        = 15,
	QSKE_BIKE2_L1        = 16,
	QSKE_BIKE2_L3        = 17,
	QSKE_BIKE2_L5        = 18,
	QSKE_BIKE3_L1        = 19,
	QSKE_BIKE3_L3        = 20,
	QSKE_BIKE3_L5        = 21,
	QSKE_SIKE_L1         = 22,
	QSKE_SIKE_L2         = 23,
	QSKE_SIKE_L3         = 24,
	QSKE_SIKE_L5         = 25,
	QSKE_NTRU_HPS_L1     = 26,
	QSKE_NTRU_HPS_L3     = 27,
	QSKE_NTRU_HPS_L5     = 28,
	QSKE_NTRU_HRSS_L3    = 29,
	QSKE_SABER_L1        = 30,
	QSKE_SABER_L3        = 31,
	QSKE_SABER_L5        = 32
};

/**
 * enum name for qske_mechanism_t.
 */
extern enum_name_t *qske_mechanism_names;

/**
 * Implementation of a Quantum-Safe Key Encapsulation Mechanism
 */
struct qske_t {

	/**
	 * Get the QSKE mechanism used.
	 *
	 * @return			QSKE mechanism
	 */
	qske_mechanism_t (*get_qske_mechanism) (qske_t *this);

	/**
	 * Get the transport-encpded QSKE public key.
	 *
	 * @param value			Transport-encoded QSKE public key (allocated)
	 * @return				TRUE if encoding successful
	 */
	bool (*get_public_key) (qske_t *this, chunk_t *value)
		__attribute__((warn_unused_result));

	/**
	 * Set the transport-encoded QSKE public key
	 *
	 * @param value			Transport-encoded QSKE public key
	 * @return				TRUE if decoding successful
	 */
	bool (*set_public_key) (qske_t *this, chunk_t value)
		__attribute__((warn_unused_result));

	/**
	 * Get the transport-encoded encrypted shared secret
	 *
	 * @param value			Transport-encode encrypted shared secret (allocated)
	 * @return				TRUE if shared secret successfully encrypted
	 */
	bool (*get_ciphertext) (qske_t *this, chunk_t *value)
		__attribute__((warn_unused_result));

	/**
	 * Set the transport-encoded encrypted shared secret and decrypt it
	 *
	 * @param value			Transport-encoded encrypted shared secret
	 * @return				TRUE if shared secret successfully decrypted
	 */
	bool (*set_ciphertext) (qske_t *this, chunk_t value)
		__attribute__((warn_unused_result));

	/**
	 * Get the shared secret
	 *
	 * @param secret		Shared secret (allocated)
	 * @return				TRUE if shared secret successfully retrieved
	 */
	bool (*get_shared_secret) (qske_t *this, chunk_t *secret)
		__attribute__((warn_unused_result));

	/**
	 * Set the internal RNG to deterministic NIST DRGB test mode
	 * Use for testing purposes only!
	 *
	 * @param enable		if TRUE enable NIST DRBG mode, else revert to RNG
	 * @param seed			Seed for initializing NIST DRBG
	 * @return				TRUE if NIST DRBG test mode available
	 */
	bool (*set_nist_drbg_mode) (qske_t *this, bool enable, chunk_t seed);

	/**
	 * Destroys a qske_t object.
	 */
	void (*destroy) (qske_t *this);
};

#endif /** QSKE_MECHANISM_H_ @}*/
