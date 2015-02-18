/*
 * Copyright (C) 2015 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include "connect_plugin.h"

#include "connect_socket.h"

#include <daemon.h>

typedef struct private_connect_plugin_t private_connect_plugin_t;

/**
 * Private data of connect plugin
 */
struct private_connect_plugin_t {

	/**
	 * Public interface
	 */
	connect_plugin_t public;

	/**
	 * Control socket
	 */
	connect_socket_t *socket;
};

METHOD(plugin_t, get_name, char*,
	private_connect_plugin_t *this)
{
	return "connect";
}

/**
 * Register listener
 */
static bool plugin_cb(private_connect_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->socket = connect_socket_create();
		return this->socket != NULL;
	}
	else
	{
		DESTROY_IF(this->socket);
		return TRUE;
	}
}

METHOD(plugin_t, get_features, int,
	private_connect_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "connect"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_connect_plugin_t *this)
{
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *connect_plugin_create()
{
	private_connect_plugin_t *this;

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
