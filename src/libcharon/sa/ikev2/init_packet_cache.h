/*
 * Copyright (C) 2018 Tobias Brunner
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
 * @defgroup init_packet_cache init_packet_cache
 * @{ @ingroup ikev2
 */

#ifndef INIT_PACKET_CACHE_H_
#define INIT_PACKET_CACHE_H_

#include <library.h>

typedef struct init_packet_cache_t init_packet_cache_t;

/**
 * Helper class to cache packet data of initial IKE messages for use in auth
 * octets.
 */
struct init_packet_cache_t {

	/**
	 * Cache data of an initial IKE packet (IKE_SA_INIT/IKE_AUX) for use in the
	 * auth octets.
	 *
	 * @param sent			TRUE if message was sent, FALSE if received
	 * @param mid			message ID of the packet
	 * @param fnr			fragment number of the packet
	 * @param data			IKE message or fragment data (cloned)
	 */
	void (*add_packet)(init_packet_cache_t *this, bool sent, uint32_t mid,
					   uint16_t fnr, chunk_t data);

	/**
	 * Get cached data of all initial IKE packets for use in the auth octets.
	 *
	 * @param sent			TRUE for sent packets, FALSE for received packets
	 * @return				concatenated packet data (allocated)
	 */
	chunk_t (*get_packets)(init_packet_cache_t *this, bool sent);

	/**
	 * Clear all cached initial IKE packet data.
	 */
	void (*clear_packets)(init_packet_cache_t *this);

	/**
	 * Destroy this instance.
	 */
	void (*destroy)(init_packet_cache_t *this);
};

/**
 * Create a init_packet_cache_t instance.
 *
 * @return					created instance
 */
init_packet_cache_t *init_packet_cache_create();

#endif /** INIT_PACKET_CACHE_H_ @}*/
