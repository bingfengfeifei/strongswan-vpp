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
 * @defgroup layered_settings_t layered_settings
 * @{ @ingroup settings
 */

#ifndef LAYERED_SETTINGS_H_
#define LAYERED_SETTINGS_H_

typedef struct layered_settings_t layered_settings_t;

#include "settings.h"

/**
 * This class enables layering of settings_t objects.
 *
 * Each instance of layered_settings_t is created with a base settings layer.
 * On top of that two layers may be added, one permanent and one is thread
 * specific (each layer may in turn be an instance of layered_settings_t).
 *
 * When settings are queried from an instance of layered_settings_t the thread
 * specific overlay is searched first, if set, then the overlay layer, if set,
 * and then the base.
 *
 * The same applies if settings are set or loaded (so the thread specific layer
 * is modified first).
 *
 * To access individual layers use the appropriate getter method.
 */
struct layered_settings_t {

	/**
	 * Implements the settings_t interface.
	 *
	 * FIXME: enumeration could get tricky, but we already have similar code for
	 * the fallback feature
	 * The add_fallback feature is also a bit tricky especially if an overlay
	 * gets added after a fallback was defined. Do we set the fallback on that
	 * overlay again?
	 * load_files[_section]() as well as the setters will only be called on the
	 * highest overlay by default (if we'd replace lib->settings with an instance
	 * of this we might have to use get_base() to reload the settings although
	 * thread-specific settings should probably be removed on e.g. ike-sa
	 * checkin)
	 */
	settings_t settings;

	/**
	 * Set the overlay settings layer.
	 *
	 * @param overlay	overlay settings FIXME: do we adopt this?
	 * @return			FIXME: should we return a previous overlay? (would easily allow to remove a layer by setting it NULL)
	 */
	settings_t *(*set_overlay)(layered_settings_t *this, settings_t *overlay);

	/**
	 * Set the thread-specific overlay settings layer.
	 *
	 * @param overlay	thread-specific overlay settings FIXME: do we adopt this?
	 * @return			FIXME: should we return a previous overlay? (would easily allow to remove a layer by setting it NULL)
	 */
	settings_t *(*set_overlay_local)(layered_settings_t *this,
									 settings_t *overlay);

	/**
	 * Get the base settings layer.
	 *
	 * @return			base settings_t object
	 */
	settings_t *(*get_base)(layered_settings_t *this);

	/**
	 * Get the overlay settings layer.
	 *
	 * @return			overlay settings_t object
	 */
	settings_t *(*get_overlay)(layered_settings_t *this);

	/**
	 * Get the thread-specific overlay settings layer.
	 *
	 * @return			thread-specific overlay settings_t object
	 */
	settings_t *(*get_overlay_local)(layered_settings_t *this);

	/**
	 * Destroy a layered_settings_t instance.
	 */
	void (*destroy)(layered_settings_t *this);
};

/**
 * Create a layered settings object.
 *
 * @param base			base settings FIXME: Do we adopt this?
 * @return				instance
 */
layered_settings_t *layered_settings_create(settings_t *base);

#endif /** LAYERED_SETTINGS_H_ @}*/
