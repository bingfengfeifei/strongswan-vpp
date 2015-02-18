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

/**
 * @defgroup connect connect
 * @ingroup cplugins
 *
 * @defgroup connect_plugin connect_plugin
 * @{ @ingroup connect
 */

#ifndef CONNECT_PLUGIN_H_
#define CONNECT_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct connect_plugin_t connect_plugin_t;

/**
 * Simple plugin to initiate/termiante connections.
 */
struct connect_plugin_t {

	/**
	 * Implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** CONNECT_PLUGIN_H_ @}*/
