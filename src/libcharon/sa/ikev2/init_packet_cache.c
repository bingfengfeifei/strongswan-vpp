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

#include "init_packet_cache.h"

#include <daemon.h>
#include <bio/bio_writer.h>
#include <collections/array.h>

typedef struct private_init_packet_cache_t private_init_packet_cache_t;

/**
 * Private data
 */
struct private_init_packet_cache_t {

	/**
	 * Public interface.
	 */
	init_packet_cache_t public;

	/**
	 * Cached packet data
	 */
	array_t *packets;
};

/**
 * Data for an initial packet
 */
typedef struct {
	/** Message ID */
	uint32_t mid;
	/** Fragment number */
	uint16_t fnr;
	/** Whether the packet was sent, or received */
	bool sent;
	/** Actual data */
	chunk_t data;
} packet_data_t;

/**
 * Destroy cached data
 */
static void packet_destroy(packet_data_t *this)
{
	chunk_free(&this->data);
	free(this);
}

METHOD(init_packet_cache_t, add_packet, void,
	private_init_packet_cache_t *this, bool sent, uint32_t mid, uint16_t fnr,
	chunk_t data)
{
	packet_data_t *packet;
	int i, insert_at = -1;

	for (i = 0; i < array_count(this->packets); i++)
	{
		array_get(this->packets, i, &packet);
		if (packet->sent != sent)
		{
			continue;
		}
		if (packet->mid == mid)
		{
			if (packet->fnr == fnr)
			{
				/* replace current data */
				chunk_free(&packet->data);
				packet->data = chunk_clone(data);
				return;
			}
			if (packet->fnr > fnr)
			{
				insert_at = i;
				break;
			}
			continue;
		}
		if (packet->mid > mid)
		{
			insert_at = i;
			break;
		}
	}
	INIT(packet,
		.mid = mid,
		.fnr = fnr,
		.sent = sent,
		.data = chunk_clone(data),
	);
	array_insert_create(&this->packets, insert_at, packet);
}

METHOD(init_packet_cache_t, get_packets, chunk_t,
	private_init_packet_cache_t *this, bool sent)
{
	packet_data_t *packet;
	bio_writer_t *writer;
	chunk_t data;
	uint32_t len = 0;
	int i;

	for (i = 0; i < array_count(this->packets); i++)
	{
		array_get(this->packets, i, &packet);
		if (packet->sent == sent)
		{
			len += packet->data.len;
		}
	}

	writer = bio_writer_create(len);
	for (i = 0; i < array_count(this->packets); i++)
	{
		array_get(this->packets, i, &packet);
		if (packet->sent == sent)
		{
			writer->write_data(writer, packet->data);
		}
	}
	data = writer->extract_buf(writer);
	writer->destroy(writer);
	return data;
}

METHOD(init_packet_cache_t, clear_packets, void,
	private_init_packet_cache_t *this)
{
	array_destroy_function(this->packets, (void*)packet_destroy, NULL);
	this->packets = NULL;
}

METHOD(init_packet_cache_t, destroy, void,
	private_init_packet_cache_t *this)
{
	clear_packets(this);
	free(this);
}

/*
 * Described in header
 */
init_packet_cache_t *init_packet_cache_create()
{
	private_init_packet_cache_t *this;

	INIT(this,
		.public = {
			.add_packet = _add_packet,
			.get_packets = _get_packets,
			.clear_packets = _clear_packets,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
