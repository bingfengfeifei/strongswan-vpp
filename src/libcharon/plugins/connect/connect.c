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

#include "connect_msg.h"

#include <arpa/inet.h>

#include <library.h>

/**
 * Send a message
 */
static int send_msg(int type, char *name)
{
	connect_msg_t msg = {
		.type = htonl(type),
	};
	stream_t *stream;
	char *uri, buffer[512];
	int count;

	uri = lib->settings->get_str(lib->settings, "charon.plugins.connect.socket",
								 "unix://" CONNECT_SOCKET);
	stream = lib->streams->connect(lib->streams, uri);
	if (!stream)
	{
		fprintf(stderr, "failed to connect to socket '%s'\n", uri);
		return 2;
	}

	snprintf(msg.name, sizeof(msg.name), "%s", name);
	if (!stream->write_all(stream, &msg, sizeof(msg)))
	{
		fprintf(stderr, "sending message failed\n");
		stream->destroy(stream);
		return 2;
	}

	while ((count = stream->read(stream, buffer, sizeof(buffer)-1, TRUE)) > 0)
	{
		buffer[count] = '\0';
		printf("%s", buffer);
	}
	if (count < 0)
	{
		fprintf(stderr, "reading response failed\n");
	}
	stream->destroy(stream);
	return 0;
}

int main(int argc, char *argv[])
{
	library_init(NULL, "connect");
	atexit(library_deinit);

	if (argc == 3 && strcmp(argv[1], "up") == 0)
	{
		return send_msg(CONNECT_INITIATE, argv[2]);
	}
	if (argc == 3 && strcmp(argv[1], "down") == 0)
	{
		return send_msg(CONNECT_TERMINATE, argv[2]);
	}
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s up <name>\n", argv[0]);
	fprintf(stderr, "  %s down <name>\n", argv[0]);
	return 1;
}
