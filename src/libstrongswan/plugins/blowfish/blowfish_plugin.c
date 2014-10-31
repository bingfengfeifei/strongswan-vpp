/*
 * Copyright (C) 2014 Tobias Brunner
 * Copyright (C) 2009 Andreas Steffen
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

#include "blowfish_plugin.h"

#include <library.h>
#include <collections/hashtable.h>
#include "blowfish_crypter.h"

typedef struct private_blowfish_plugin_t private_blowfish_plugin_t;

/**
 * private data of blowfish_plugin
 */
struct private_blowfish_plugin_t {

	/**
	 * public functions
	 */
	blowfish_plugin_t public;
};

/**
 * proposal tokens for variable key lengths
 */
static hashtable_t *tokens;


METHOD(plugin_t, get_name, char*,
	private_blowfish_plugin_t *this)
{
	return "blowfish";
}

METHOD(plugin_t, get_features, int,
	private_blowfish_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(CRYPTER, blowfish_crypter_create),
			PLUGIN_PROVIDE(CRYPTER, ENCR_BLOWFISH, 0),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_blowfish_plugin_t *this)
{
	enumerator_t *enumerator;
	proposal_token_t *token;
	char *name;

	enumerator = tokens->create_enumerator(tokens);
	while (enumerator->enumerate(enumerator, &name, &token))
	{
		free(name);
		free(token);
	}
	enumerator->destroy(enumerator);
	tokens->destroy(tokens);
	free(this);
}

/**
 * Parse blowfish<keylen> for key lengths other than 128, 192 and 256.
 */
static proposal_token_t *blowfish_keyword(const char *algname)
{
	proposal_token_t *token;
	int keylen;

	if (!strcasepfx(algname, "blowfish"))
	{
		return NULL;
	}
	token = tokens->get(tokens, algname);
	if (token)
	{
		return token;
	}
	keylen = atoi(algname + strlen("blowfish"));
	if (keylen < 40 || keylen > 448)
	{
		return NULL;
	}
	INIT(token,
		.name = strdup(algname),
		.type = ENCRYPTION_ALGORITHM,
		.algorithm = ENCR_BLOWFISH,
		.keysize = keylen,
	);
	tokens->put(tokens, token->name, token);
	return token;
}

/*
 * see header file
 */
plugin_t *blowfish_plugin_create()
{
	private_blowfish_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	tokens = hashtable_create(hashtable_hash_str, hashtable_equals_str, 4);
	lib->proposal->register_algname_parser(lib->proposal, blowfish_keyword);

	return &this->public.plugin;
}
