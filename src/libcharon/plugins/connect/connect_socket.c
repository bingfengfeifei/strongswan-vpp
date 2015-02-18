/*
 * Copyright (C) 2013-2015 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include "connect_socket.h"

#include <daemon.h>
#include <collections/array.h>

#include "connect_msg.h"

#define CONNECT_LOG_LEVEL 1

typedef struct private_connect_socket_t private_connect_socket_t;

/**
 * Private data of a connect_socket_t object
 */
struct private_connect_socket_t {

	/**
	 * Public interface
	 */
	connect_socket_t public;

	/**
	 * Connect stream service
	 */
	stream_service_t *service;
};

/**
 * Logging to the connect socket
 */
static bool connect_log(FILE *out, debug_t group, level_t level,
						ike_sa_t *ike_sa, char *message)
{
	if (level <= CONNECT_LOG_LEVEL)
	{
		if (fprintf(out, "%s", message) < 0 ||
			fprintf(out, "\n") < 0 ||
			fflush(out) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Initiate the connection with the given config
 */
static void perform_initiate(private_connect_socket_t *this, char *name,
		peer_cfg_t *peer_cfg, child_cfg_t *child_cfg, FILE *out)
{
	status_t status;

	status = charon->controller->initiate(charon->controller, peer_cfg,
							child_cfg, (controller_cb_t)connect_log, out, 0);
	switch (status)
	{
		case SUCCESS:
			fprintf(out, "connection '%s' established successfully\n", name);
			break;
		default:
		case FAILED:
			fprintf(out, "establishing connection '%s' failed\n", name);
			break;
	}
}

/**
 * Initiate the connection with the given name
 */
static void initiate(private_connect_socket_t *this, char *name, FILE *out)
{
	child_cfg_t *child_cfg = NULL;
	peer_cfg_t *peer_cfg;
	enumerator_t *enumerator;
	bool empty = TRUE;

	DBG1(DBG_CFG, "connect: initiate '%s'", name);

	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends, name);
	if (peer_cfg)
	{
		child_cfg = get_child_from_peer(peer_cfg, name);
		if (child_cfg == NULL)
		{
			enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (enumerator->enumerate(enumerator, &child_cfg))
			{
				empty = FALSE;
				perform_initiate(this, name, peer_cfg->get_ref(peer_cfg),
								 child_cfg->get_ref(child_cfg), out);
			}
			enumerator->destroy(enumerator);

			if (empty)
			{
				DBG1(DBG_CFG, "no child config named '%s'", name);
				fprintf(out, "no child config named '%s'\n", name);
			}
			peer_cfg->destroy(peer_cfg);
			return;
		}
	}
	else
	{
		enumerator = charon->backends->create_peer_cfg_enumerator(
							charon->backends, NULL, NULL, NULL, NULL, IKE_ANY);
		while (enumerator->enumerate(enumerator, &peer_cfg))
		{
			child_cfg = get_child_from_peer(peer_cfg, name);
			if (child_cfg)
			{
				peer_cfg->get_ref(peer_cfg);
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (child_cfg == NULL)
		{
			DBG1(DBG_CFG, "no config named '%s'", name);
			fprintf(out, "no config named '%s'\n", name);
			return;
		}
	}
	perform_initiate(this, name, peer_cfg, child_cfg, out);
}

/**
 * Terminate the connection with the given name
 */
static void terminate(private_connect_socket_t *this, char *name, FILE *out)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	array_t *ike_sas;
	status_t status;
	u_int32_t id, *current;

	DBG1(DBG_CFG, "connect: terminate '%s'", name);

	ike_sas = array_create(sizeof(u_int32_t), 1);
	enumerator = charon->controller->create_ike_sa_enumerator(
													charon->controller, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		if (streq(name, ike_sa->get_name(ike_sa)))
		{
			id = ike_sa->get_unique_id(ike_sa);
			array_insert(ike_sas, ARRAY_TAIL, &id);
		}
	}
	enumerator->destroy(enumerator);

	enumerator = array_create_enumerator(ike_sas);
	while (enumerator->enumerate(enumerator, &current))
	{
		status = charon->controller->terminate_ike(charon->controller,
							*current, (controller_cb_t)connect_log, out, 0);
		switch (status)
		{
			case SUCCESS:
				fprintf(out, "IKE_SA[%d] closed successfully\n", *current);
				break;
			default:
			case FAILED:
				fprintf(out, "closing IKE_SA[%d] failed\n", *current);
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!array_count(ike_sas))
	{
		DBG1(DBG_CFG, "no IKE_SA named '%s'", name);
		fprintf(out, "no IKE_SA named '%s'\n", name);
	}
	array_destroy(ike_sas);
}

/**
 * Dispatch a received message
 */
static bool on_accept(private_connect_socket_t *this, stream_t *stream)
{
	connect_msg_t msg;
	FILE *out;

	if (stream->read_all(stream, &msg, sizeof(msg)))
	{
		msg.name[sizeof(msg.name) - 1] = '\0';
		out = stream->get_file(stream);
		if (!out)
		{
			DBG1(DBG_CFG, "creating connect output stream failed");
			return FALSE;
		}
		switch (ntohl(msg.type))
		{
			case CONNECT_INITIATE:
				initiate(this, msg.name, out);
				break;
			case CONNECT_TERMINATE:
				terminate(this, msg.name, out);
				break;
			default:
				DBG1(DBG_CFG, "received unknown connect command");
				break;
		}
		fclose(out);
	}
	return FALSE;
}

METHOD(connect_socket_t, destroy, void,
	private_connect_socket_t *this)
{
	this->service->destroy(this->service);
	free(this);
}

/**
 * See header
 */
connect_socket_t *connect_socket_create()
{
	private_connect_socket_t *this;
	char *uri;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
	);

	uri = lib->settings->get_str(lib->settings,
					"%s.plugins.connect.socket", "unix://" CONNECT_SOCKET,
					lib->ns);
	this->service = lib->streams->create_service(lib->streams, uri, 10);
	if (!this->service)
	{
		DBG1(DBG_CFG, "creating connect socket failed");
		free(this);
		return NULL;
	}

	this->service->on_accept(this->service, (stream_service_cb_t)on_accept,
							 this, JOB_PRIO_CRITICAL, 0);

	return &this->public;
}
