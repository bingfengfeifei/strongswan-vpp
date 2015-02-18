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
 * @defgroup connect_socket connect_socket
 * @{ @ingroup connect
 */

#ifndef CONNECT_SOCKET_H_
#define CONNECT_SOCKET_H_

typedef struct connect_socket_t connect_socket_t;

/**
 * Control socket
 */
struct connect_socket_t {

	/**
	 * Destroy a connect_socket_t
	 */
	void (*destroy)(connect_socket_t *this);
};

/**
 * Create a connect_socket instance
 */
connect_socket_t *connect_socket_create();

#endif /** CONNECT_SOCKET_H_ @}*/
