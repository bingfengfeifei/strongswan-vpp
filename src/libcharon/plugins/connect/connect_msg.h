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
 * @defgroup connect_msg connect_msg
 * @{ @ingroup connect
 */

#ifndef CONNECT_MSG_H_
#define CONNECT_MSG_H_

#define CONNECT_SOCKET IPSEC_PIDDIR "/charon.cnct"

typedef struct connect_msg_t connect_msg_t;

/**
 * Message type
 */
enum {
	/* initiate a connection */
	CONNECT_INITIATE = 1,
	/* terminate a connection */
	CONNECT_TERMINATE = 2,
};

/**
 * Message to exchange over socket
 */
struct connect_msg_t {
	/** message type */
	int type;
	/** null terminated connection name */
	char name[128];
} __attribute__((packed));

#endif /** CONNECT_MSG_H_ @}*/
