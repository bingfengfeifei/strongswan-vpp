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

#include "test_suite.h"

#include <oqs_qske.h>

#include <library.h>

typedef struct {
	qske_mechanism_t mechanism;
	int count;
	chunk_t seed;
	chunk_t pk;
	chunk_t ct;
	chunk_t ss;
} kat_t;

static kat_t kat[] = {
	#include "test_oqs_kat_newhope_l1.h"
	#include "test_oqs_kat_newhope_l5.h"
	#include "test_oqs_kat_frodo_aes_l1.h"
	#include "test_oqs_kat_frodo_aes_l3.h"
	#include "test_oqs_kat_frodo_shake_l1.h"
	#include "test_oqs_kat_frodo_shake_l3.h"
	#include "test_oqs_kat_kyber_l1.h"
	#include "test_oqs_kat_kyber_l3.h"
	#include "test_oqs_kat_kyber_l5.h"
	#include "test_oqs_kat_bike1_l1.h"
	#include "test_oqs_kat_bike1_l3.h"
	#include "test_oqs_kat_bike1_l5.h"
	#include "test_oqs_kat_bike2_l1.h"
	#include "test_oqs_kat_bike2_l3.h"
	#include "test_oqs_kat_bike2_l5.h"
	#include "test_oqs_kat_bike3_l1.h"
	#include "test_oqs_kat_bike3_l3.h"
	#include "test_oqs_kat_bike3_l5.h"
	#include "test_oqs_kat_sike_l1.h"
	#include "test_oqs_kat_sike_l3.h"
	#include "test_oqs_kat_saber_l1.h"
	#include "test_oqs_kat_saber_l3.h"
	#include "test_oqs_kat_saber_l3.h"
	#include "test_oqs_kat_lima_2p_l3.h"
	#include "test_oqs_kat_lima_2p_l5.h"
	#include "test_oqs_kat_lima_sp_l1.h"
	#include "test_oqs_kat_lima_sp_l2.h"
	#include "test_oqs_kat_lima_sp_l3.h"
	#include "test_oqs_kat_lima_sp_l5.h"
};

START_TEST(test_oqs_kat_nist)
{
	chunk_t pk, ct, i_ss, r_ss;
	qske_t *i_qske, *r_qske;

	i_qske = (qske_t*)oqs_qske_create(kat[_i].mechanism);
	ck_assert(i_qske != NULL);

	/* Set NIST DRBG seed value*/
	ck_assert(i_qske->set_nist_drbg_mode(i_qske, TRUE, kat[_i].seed));

	/* Check public key value */
	ck_assert(i_qske->get_public_key(i_qske, &pk));
	ck_assert_chunk_eq(pk, kat[_i].pk);

	r_qske = (qske_t*)oqs_qske_create(kat[_i].mechanism);
	ck_assert(r_qske != NULL);
	ck_assert(r_qske->set_public_key(r_qske, pk));

	/* Check ciphertext value */
	ck_assert(r_qske->get_ciphertext(r_qske, &ct));
	ck_assert_chunk_eq(ct, kat[_i].ct);

	/* Check shared secret value */
	ck_assert(r_qske->get_shared_secret(r_qske, &r_ss));
	ck_assert_chunk_eq(r_ss, kat[_i].ss);

	/* Check equivalence of shared secrets */
	ck_assert(i_qske->set_ciphertext(i_qske, ct));
	ck_assert(i_qske->get_shared_secret(i_qske, &i_ss));
	ck_assert_chunk_eq(i_ss, r_ss);

	/* Cleanup */
	chunk_clear(&i_ss);
	chunk_clear(&r_ss);
	chunk_free(&pk);
	chunk_free(&ct);
	i_qske->set_nist_drbg_mode(i_qske, FALSE, chunk_empty);
	i_qske->destroy(i_qske);
	r_qske->destroy(r_qske);
}
END_TEST


Suite *oqs_kat_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("oqs_kat");

	tc = tcase_create("nist");
	tcase_add_loop_test(tc, test_oqs_kat_nist, 0, countof(kat));
	suite_add_tcase(s, tc);

	return s;
}
