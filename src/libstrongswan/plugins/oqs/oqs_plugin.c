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

#include "oqs_plugin.h"
#include "oqs_qske.h"

#include <library.h>

typedef struct private_oqs_plugin_t private_oqs_plugin_t;

/**
 * private data of oqs_plugin
 */
struct private_oqs_plugin_t {

	/**
	 * public functions
	 */
	oqs_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_oqs_plugin_t *this)
{
	return "oqs";
}

METHOD(plugin_t, get_features, int,
	private_oqs_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		/* QSKE groups */
		PLUGIN_REGISTER(QSKE, oqs_qske_create),
			PLUGIN_PROVIDE(QSKE, QSKE_NEWHOPE_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_NEWHOPE_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_FRODO_AES_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_FRODO_AES_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_FRODO_SHAKE_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_FRODO_SHAKE_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_KYBER_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_KYBER_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_KYBER_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE1_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE1_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE1_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE2_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE2_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE2_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE3_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE3_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_BIKE3_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_SIKE_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_SIKE_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_SABER_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_SABER_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_SABER_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_2P_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_2P_L5),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_SP_L1),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_SP_L2),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_SP_L3),
			PLUGIN_PROVIDE(QSKE, QSKE_LIMA_SP_L5)
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_oqs_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *oqs_plugin_create()
{
	private_oqs_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

