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

#include <time.h>

const int count = 10;

START_TEST(test_oqs_good)
{
	chunk_t i_msg, r_msg, i_shared_secret, r_shared_secret;
	qske_mechanism_t mechanism = _i;
	qske_t *i_qske, *r_qske;
	struct timespec start, stop;
	int i;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

	for (i = 0; i < count; i++)
	{
		if (i == 0)
		{
			i_qske = (qske_t*)oqs_qske_create(QSKE_NONE);
			ck_assert(i_qske == NULL);
		}
		i_qske = (qske_t*)oqs_qske_create(mechanism);
		ck_assert(i_qske != NULL);
		ck_assert(i_qske->get_qske_mechanism(i_qske) == mechanism);

		if (i == 0)
		{
			ck_assert(i_qske->get_public_key(i_qske, &i_msg));
			chunk_free(&i_msg);
		}
		ck_assert(i_qske->get_public_key(i_qske, &i_msg));

		r_qske = (qske_t*)oqs_qske_create(mechanism);
		ck_assert(r_qske != NULL);

		if (i == 0)
		{
			ck_assert(r_qske->set_public_key(r_qske, i_msg));
		}
		ck_assert(r_qske->set_public_key(r_qske, i_msg));

		if (i == 0)
		{
			ck_assert(r_qske->get_ciphertext(r_qske, &r_msg));
			chunk_free(&r_msg);
		}
		ck_assert(r_qske->get_ciphertext(r_qske, &r_msg));
		ck_assert(r_qske->get_shared_secret(r_qske, &r_shared_secret));

		if (i == 0)
		{
			ck_assert(i_qske->set_ciphertext(i_qske, r_msg));
		}
		ck_assert(i_qske->set_ciphertext(i_qske, r_msg));
		ck_assert(i_qske->get_shared_secret(i_qske, &i_shared_secret));
		ck_assert_chunk_eq(i_shared_secret, r_shared_secret);

		/* cleanup */
		chunk_clear(&i_shared_secret);
		chunk_clear(&r_shared_secret);
		chunk_free(&i_msg);
		chunk_free(&r_msg);
		i_qske->destroy(i_qske);
		r_qske->destroy(r_qske);
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &stop);

	DBG0(DBG_LIB, "\n%d %N loops in %d ms", count,
				  qske_mechanism_names, mechanism,
				  (stop.tv_nsec - start.tv_nsec) / 1000000 +
				  (stop.tv_sec - start.tv_sec) * 1000);
}
END_TEST

START_TEST(test_oqs_wrong)
{
	chunk_t i_msg, r_msg, i_shared_secret, r_shared_secret;
	qske_t *i_qske, *r_qske;
	qske_mechanism_t mechanism = _i;

	i_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(i_qske != NULL);
	ck_assert(i_qske->get_public_key(i_qske, &i_msg));

	r_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(r_qske != NULL);
	ck_assert(!r_qske->get_ciphertext(r_qske, &r_msg));
	ck_assert(!r_qske->get_shared_secret(r_qske, &r_shared_secret));
	ck_assert(r_qske->set_public_key(r_qske, i_msg));
	ck_assert(r_qske->get_ciphertext(r_qske, &r_msg));
	ck_assert(r_qske->get_shared_secret(r_qske, &r_shared_secret));

	DBG0(DBG_LIB, "\n%N shared secret length of %u bytes",
				   qske_mechanism_names, mechanism, r_shared_secret.len);

	/* destroy 1st instance of i_qske */
	i_qske->destroy(i_qske);
	chunk_free(&i_msg);

	/* create 2nd instance of i_qske */
	i_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(i_qske != NULL);
	ck_assert(!i_qske->set_ciphertext(i_qske, r_msg));
	ck_assert(i_qske->get_public_key(i_qske, &i_msg));
	if (i_qske->set_ciphertext(i_qske, r_msg))
	{
		ck_assert(i_qske->get_shared_secret(i_qske, &i_shared_secret));
		ck_assert(!chunk_equals(i_shared_secret, r_shared_secret));
		chunk_clear(&i_shared_secret);
		chunk_clear(&r_shared_secret);
	}

	/* cleanup */
	chunk_free(&i_msg);
	chunk_free(&r_msg);
	i_qske->destroy(i_qske);
	r_qske->destroy(r_qske);
}
END_TEST

START_TEST(test_oqs_fail_i)
{
	qske_t *i_qske, *r_qske;
	qske_mechanism_t mechanism = _i;
	char buf_ff[16384];
	chunk_t i_msg, r_msg, fail_msg;


	memset(buf_ff, 0xff, sizeof(buf_ff));
	fail_msg = chunk_create(buf_ff, sizeof(buf_ff));

	i_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(i_qske != NULL);
	ck_assert(i_qske->get_public_key(i_qske, &i_msg));

	r_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(r_qske != NULL);
	ck_assert(r_qske->set_public_key(r_qske, i_msg));
	ck_assert(r_qske->get_ciphertext(r_qske, &r_msg));

	DBG0(DBG_LIB, "\n%N ciphertext length of %u bytes",
				   qske_mechanism_names, mechanism, r_msg.len);
	fail_msg.len = 0;
	ck_assert(!i_qske->set_ciphertext(i_qske, fail_msg));
	fail_msg.len = 1;
	ck_assert(!i_qske->set_ciphertext(i_qske, fail_msg));
	fail_msg.len = r_msg.len - 1;
	ck_assert(!i_qske->set_ciphertext(i_qske, fail_msg));
	fail_msg.len = r_msg.len + 1;
	ck_assert(!i_qske->set_ciphertext(i_qske, fail_msg));

	chunk_free(&i_msg);
	chunk_free(&r_msg);
	i_qske->destroy(i_qske);
	r_qske->destroy(r_qske);
}
END_TEST

START_TEST(test_oqs_fail_r)
{
	qske_t *i_qske, *r_qske;
	qske_mechanism_t mechanism = _i;
	char buf_ff[18432];
	chunk_t i_msg, fail_msg;

	memset(buf_ff, 0xff, sizeof(buf_ff));
	fail_msg = chunk_create(buf_ff, sizeof(buf_ff));

	i_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(i_qske != NULL);
	ck_assert(i_qske->get_public_key(i_qske, &i_msg));

	r_qske = (qske_t*)oqs_qske_create(mechanism);
	ck_assert(r_qske != NULL);

	DBG0(DBG_LIB, "\n%N public key length of %u bytes",
				   qske_mechanism_names, mechanism, i_msg.len);
	fail_msg.len = 0;
	ck_assert(!r_qske->set_public_key(r_qske, fail_msg));
	fail_msg.len = 1;
	ck_assert(!r_qske->set_public_key(r_qske, fail_msg));
	fail_msg.len = i_msg.len - 1;
	ck_assert(!r_qske->set_public_key(r_qske, fail_msg));
	fail_msg.len = i_msg.len + 1;
	ck_assert(!r_qske->set_public_key(r_qske, fail_msg));

	chunk_free(&i_msg);
	i_qske->destroy(i_qske);
	r_qske->destroy(r_qske);
}
END_TEST

Suite *oqs_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("oqs");

	tc = tcase_create("good");
	test_case_set_timeout(tc, 30);
	tcase_add_loop_test(tc, test_oqs_good, QSKE_NEWHOPE_L1, QSKE_LIMA_SP_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("wrong");
	tcase_add_loop_test(tc, test_oqs_wrong, QSKE_NEWHOPE_L1, QSKE_LIMA_SP_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("fail_i");
	tcase_add_loop_test(tc, test_oqs_fail_i, QSKE_NEWHOPE_L1, QSKE_LIMA_SP_L5 + 1);
	suite_add_tcase(s, tc);

	tc = tcase_create("fail_r");
	tcase_add_loop_test(tc, test_oqs_fail_r, QSKE_NEWHOPE_L1, QSKE_LIMA_SP_L5 + 1);
	suite_add_tcase(s, tc);

	return s;
}
