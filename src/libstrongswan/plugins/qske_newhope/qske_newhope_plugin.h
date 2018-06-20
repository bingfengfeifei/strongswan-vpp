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
 * @defgroup qske_qske_newhope_p qske_newhope
 * @ingroup plugins
 *
 * @defgroup qske_newhope_plugin qske_newhope_plugin
 * @{ @ingroup qske_newhope_p
 */

#ifndef QSKE_NEWHOPE_PLUGIN_H_
#define QSKE_NEWHOPE_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct qske_newhope_plugin_t qske_newhope_plugin_t;

/**
 * Plugin implementing New Hope-based key exchange
 */
struct qske_newhope_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** QSKE_NEWHOPE_PLUGIN_H_ @}*/
