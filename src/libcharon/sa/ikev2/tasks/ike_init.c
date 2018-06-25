/*
 * Copyright (C) 2008-2019 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "ike_init.h"

#include <string.h>

#include <daemon.h>
#include <bio/bio_reader.h>
#include <bio/bio_writer.h>
#include <sa/ikev2/keymat_v2.h>
#include <crypto/diffie_hellman.h>
#include <crypto/hashers/hash_algorithm_set.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/qske_payload.h>
#include <encoding/payloads/nonce_payload.h>

/** maximum retries to do with cookies/other dh groups */
#define MAX_RETRIES 5

typedef struct private_ike_init_t private_ike_init_t;

/**
 * Private members of a ike_init_t task.
 */
struct private_ike_init_t {

	/**
	 * Public methods and task_t interface.
	 */
	ike_init_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * diffie hellman group to use
	 */
	diffie_hellman_group_t dh_group;

	/**
	 * diffie hellman key exchange
	 */
	diffie_hellman_t *dh;

	/**
	 * Applying DH public value failed?
	 */
	bool dh_failed;

	/**
	 * QSKE mechanism to use
	 */
	qske_mechanism_t qske_mechanism;

	/**
	 * QSKE mechanism implementation
	 */
	qske_t *qske;

	/**
	 * Creating QSKE implementation failed
	 */
	bool qske_failed;

	/**
	 * Keymat derivation (from IKE_SA)
	 */
	keymat_v2_t *keymat;

	/**
	 * nonce chosen by us
	 */
	chunk_t my_nonce;

	/**
	 * nonce chosen by peer
	 */
	chunk_t other_nonce;

	/**
	 * nonce generator
	 */
	nonce_gen_t *nonceg;

	/**
	 * Negotiated proposal used for IKE_SA
	 */
	proposal_t *proposal;

	/**
	 * Old IKE_SA which gets rekeyed
	 */
	ike_sa_t *old_sa;

	/**
	 * cookie received from responder
	 */
	chunk_t cookie;

	/**
	 * retries done so far after failure (cookie or bad dh group)
	 */
	u_int retry;

	/**
	 * Whether to use Signature Authentication as per RFC 7427
	 */
	bool signature_authentication;

	/**
	 * Whether to follow IKEv2 redirects as per RFC 5685
	 */
	bool follow_redirects;
};

/**
 * Allocate our own nonce value
 */
static bool generate_nonce(private_ike_init_t *this)
{
	if (!this->nonceg)
	{
		DBG1(DBG_IKE, "no nonce generator found to create nonce");
		return FALSE;
	}
	if (!this->nonceg->allocate_nonce(this->nonceg, NONCE_SIZE,
									  &this->my_nonce))
	{
		DBG1(DBG_IKE, "nonce allocation failed");
		return FALSE;
	}
	return TRUE;
}

/**
 * Notify the peer about the hash algorithms we support or expect,
 * as per RFC 7427
 */
static void send_supported_hash_algorithms(private_ike_init_t *this,
										   message_t *message)
{
	hash_algorithm_set_t *algos;
	enumerator_t *enumerator, *rounds;
	bio_writer_t *writer;
	hash_algorithm_t hash;
	peer_cfg_t *peer;
	auth_cfg_t *auth;
	auth_rule_t rule;
	signature_params_t *config;
	int written;
	size_t len = BUF_LEN;
	char buf[len];
	char *pos = buf;
	char *plugin_name;

	algos = hash_algorithm_set_create();
	peer = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (peer)
	{
		rounds = peer->create_auth_cfg_enumerator(peer, FALSE);
		while (rounds->enumerate(rounds, &auth))
		{
			enumerator = auth->create_enumerator(auth);
			while (enumerator->enumerate(enumerator, &rule, &config))
			{
				if (rule == AUTH_RULE_IKE_SIGNATURE_SCHEME)
				{
					hash = hasher_from_signature_scheme(config->scheme,
														config->params);
					if (hasher_algorithm_for_ikev2(hash))
					{
						algos->add(algos, hash);
					}
				}
			}
			enumerator->destroy(enumerator);
		}
		rounds->destroy(rounds);
	}

	if (!algos->count(algos))
	{
		enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
		while (enumerator->enumerate(enumerator, &hash, &plugin_name))
		{
			if (hasher_algorithm_for_ikev2(hash))
			{
				algos->add(algos, hash);
			}
		}
		enumerator->destroy(enumerator);
	}

	if (algos->count(algos))
	{
		writer = bio_writer_create(0);
		enumerator = algos->create_enumerator(algos);
		while (enumerator->enumerate(enumerator, &hash))
		{
			writer->write_uint16(writer, hash);

			/* generate debug output */
			written = snprintf(pos, len, " %N", hash_algorithm_short_names,
							   hash);
			if (written > 0 && written < len)
			{
				pos += written;
				len -= written;
			}
		}
		enumerator->destroy(enumerator);
		message->add_notify(message, FALSE, SIGNATURE_HASH_ALGORITHMS,
							writer->get_buf(writer));
		writer->destroy(writer);

		*pos = '\0';
		DBG2(DBG_CFG, "sending supported signature hash algorithms:%s", buf);
	}
	algos->destroy(algos);
}

/**
 * Store algorithms supported by other peer
 */
static void handle_supported_hash_algorithms(private_ike_init_t *this,
											 notify_payload_t *notify)
{
	bio_reader_t *reader;
	uint16_t algo;
	int written;
	size_t len = BUF_LEN;
	char buf[len];
	char *pos = buf;
	bool added = FALSE;

	reader = bio_reader_create(notify->get_notification_data(notify));
	while (reader->remaining(reader) >= 2 && reader->read_uint16(reader, &algo))
	{
		if (hasher_algorithm_for_ikev2(algo))
		{
			this->keymat->add_hash_algorithm(this->keymat, algo);
			added = TRUE;

			/* generate debug output */
			written = snprintf(pos, len, " %N", hash_algorithm_short_names,
							   algo);
			if (written > 0 && written < len)
			{
				pos += written;
				len -= written;
			}
		}
	}
	reader->destroy(reader);

	*pos = '\0';
	DBG2(DBG_CFG, "received supported signature hash algorithms:%s", buf);

	if (added)
	{
		this->ike_sa->enable_extension(this->ike_sa, EXT_SIGNATURE_AUTH);
	}
}

/**
 * Check whether to send a USE_PPK notify
 */
static bool send_use_ppk(private_ike_init_t *this)
{
	peer_cfg_t *peer;
	enumerator_t *keys;
	shared_key_t *key;
	bool use_ppk = FALSE;

	if (this->initiator)
	{
		peer = this->ike_sa->get_peer_cfg(this->ike_sa);
		if (peer->get_ppk_id(peer))
		{
			use_ppk = TRUE;
		}
	}
	else if (this->ike_sa->supports_extension(this->ike_sa, EXT_PPK))
	{
		/* check if we have at least one PPK available */
		keys = lib->credmgr->create_shared_enumerator(lib->credmgr, SHARED_PPK,
													  NULL, NULL);
		if (keys->enumerate(keys, &key, NULL, NULL))
		{
			use_ppk = TRUE;
		}
		keys->destroy(keys);
	}
	return use_ppk;
}

/**
 * Builds an SA payload as initiator, modified according to the proposed
 * DH group and QSKE mechanism.
 */
static sa_payload_t *build_sa_payload(private_ike_init_t *this, ike_sa_id_t *id,
									  ike_cfg_t *cfg)
{
	linked_list_t *proposals, *others;
	enumerator_t *enumerator;
	proposal_t *proposal;
	sa_payload_t *sa_payload;

	proposals = cfg->get_proposals(cfg);
	others = linked_list_create();
	enumerator = proposals->create_enumerator(proposals);
	while (enumerator->enumerate(enumerator, (void**)&proposal))
	{
		/* include SPI of new IKE_SA when we are rekeying */
		if (this->old_sa)
		{
			proposal->set_spi(proposal, id->get_initiator_spi(id));
		}
		/* move the selected DH group to the front of the proposal */
		if (!proposal->promote_transform(proposal, DIFFIE_HELLMAN_GROUP,
										 this->dh_group))
		{	/* the proposal does not include the group, move to the back */
			proposals->remove_at(proposals, enumerator);
			others->insert_last(others, proposal);
		}
		else if (this->qske &&
				 !proposal->promote_transform(proposal, QSKE_MECHANISM,
											  this->qske_mechanism))
		{	/* same for QSKE mechanisms, but add them before groups that don't
			 * contain the DH group */
			proposals->remove_at(proposals, enumerator);
			others->insert_first(others, proposal);
		}
	}
	enumerator->destroy(enumerator);
	/* add proposals that don't contain the selected group */
	enumerator = others->create_enumerator(others);
	while (enumerator->enumerate(enumerator, (void**)&proposal))
	{	/* no need to remove from the list as we destroy it anyway*/
		proposals->insert_last(proposals, proposal);
	}
	enumerator->destroy(enumerator);
	others->destroy(others);

	sa_payload = sa_payload_create_from_proposals_v2(proposals);
	proposals->destroy_offset(proposals, offsetof(proposal_t, destroy));
	return sa_payload;
}

/**
 * build the payloads for the message
 */
static bool build_payloads(private_ike_init_t *this, message_t *message)
{
	sa_payload_t *sa_payload;
	ke_payload_t *ke_payload;
	qske_payload_t *qske_payload;
	nonce_payload_t *nonce_payload;
	ike_sa_id_t *id;
	ike_cfg_t *ike_cfg;

	id = this->ike_sa->get_id(this->ike_sa);

	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);

	if (this->initiator)
	{
		sa_payload = build_sa_payload(this, id, ike_cfg);
	}
	else
	{
		if (this->old_sa)
		{
			/* include SPI of new IKE_SA when we are rekeying */
			this->proposal->set_spi(this->proposal, id->get_responder_spi(id));
		}
		sa_payload = sa_payload_create_from_proposal_v2(this->proposal);
	}
	message->add_payload(message, (payload_t*)sa_payload);

	ke_payload = ke_payload_create_from_diffie_hellman(PLV2_KEY_EXCHANGE,
													   this->dh);
	if (!ke_payload)
	{
		DBG1(DBG_IKE, "creating KE payload failed");
		return FALSE;
	}
	message->add_payload(message, (payload_t*)ke_payload);

	nonce_payload = nonce_payload_create(PLV2_NONCE);
	nonce_payload->set_nonce(nonce_payload, this->my_nonce);
	message->add_payload(message, (payload_t*)nonce_payload);

	if (this->qske)
	{
		qske_payload = qske_payload_create_from_qske(this->qske,
													 this->initiator);
		if (!qske_payload)
		{
			DBG1(DBG_IKE, "failed to create QSKE payload");
			return FALSE;
		}
		message->add_payload(message, (payload_t*)qske_payload);
	}

	/* negotiate fragmentation if we are not rekeying */
	if (!this->old_sa &&
		 ike_cfg->fragmentation(ike_cfg) != FRAGMENTATION_NO)
	{
		if (this->initiator ||
			this->ike_sa->supports_extension(this->ike_sa,
											 EXT_IKE_FRAGMENTATION))
		{
			message->add_notify(message, FALSE, FRAGMENTATION_SUPPORTED,
								chunk_empty);
		}
	}
	/* submit supported hash algorithms for signature authentication */
	if (!this->old_sa && this->signature_authentication)
	{
		if (this->initiator ||
			this->ike_sa->supports_extension(this->ike_sa,
											 EXT_SIGNATURE_AUTH))
		{
			send_supported_hash_algorithms(this, message);
		}
	}
	/* notify other peer if we support redirection */
	if (!this->old_sa && this->initiator && this->follow_redirects)
	{
		identification_t *gateway;
		host_t *from;
		chunk_t data;

		from = this->ike_sa->get_redirected_from(this->ike_sa);
		if (from)
		{
			gateway = identification_create_from_sockaddr(
													from->get_sockaddr(from));
			data = redirect_data_create(gateway, chunk_empty);
			message->add_notify(message, FALSE, REDIRECTED_FROM, data);
			chunk_free(&data);
			gateway->destroy(gateway);
		}
		else
		{
			message->add_notify(message, FALSE, REDIRECT_SUPPORTED,
								chunk_empty);
		}
	}
	/* notify the peer if we want to use/support PPK */
	if (!this->old_sa && send_use_ppk(this))
	{
		message->add_notify(message, FALSE, USE_PPK, chunk_empty);
	}
	/* notify the peer if we accept childless IKE_SAs */
	if (!this->old_sa && !this->initiator &&
		 ike_cfg->childless(ike_cfg) != CHILDLESS_NEVER)
	{
		message->add_notify(message, FALSE, CHILDLESS_IKEV2_SUPPORTED,
							chunk_empty);
	}
	return TRUE;
}

/**
 * Process the SA payload and select a proposal
 */
static void process_sa_payload(private_ike_init_t *this, message_t *message,
							   sa_payload_t *sa_payload)
{
	ike_cfg_t *ike_cfg, *cfg, *alt_cfg = NULL;
	enumerator_t *enumerator;
	linked_list_t *proposal_list;
	host_t *me, *other;
	bool private, prefer_configured;

	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);

	proposal_list = sa_payload->get_proposals(sa_payload);
	private = this->ike_sa->supports_extension(this->ike_sa, EXT_STRONGSWAN);
	prefer_configured = lib->settings->get_bool(lib->settings,
							"%s.prefer_configured_proposals", TRUE, lib->ns);

	this->proposal = ike_cfg->select_proposal(ike_cfg, proposal_list, private,
											  prefer_configured);
	if (!this->proposal)
	{
		if (!this->initiator && !this->old_sa)
		{
			me = message->get_destination(message);
			other = message->get_source(message);
			enumerator = charon->backends->create_ike_cfg_enumerator(
											charon->backends, me, other, IKEV2);
			while (enumerator->enumerate(enumerator, &cfg))
			{
				if (ike_cfg == cfg)
				{	/* already tried and failed */
					continue;
				}
				DBG1(DBG_IKE, "no matching proposal found, trying alternative "
					 "config");
				this->proposal = cfg->select_proposal(cfg, proposal_list,
													private, prefer_configured);
				if (this->proposal)
				{
					alt_cfg = cfg->get_ref(cfg);
					break;
				}
			}
			enumerator->destroy(enumerator);
		}
		if (alt_cfg)
		{
			this->ike_sa->set_ike_cfg(this->ike_sa, alt_cfg);
			alt_cfg->destroy(alt_cfg);
		}
		else
		{
			charon->bus->alert(charon->bus, ALERT_PROPOSAL_MISMATCH_IKE,
							   proposal_list);
		}
	}
	proposal_list->destroy_offset(proposal_list,
								  offsetof(proposal_t, destroy));
}

/**
 * Process a QSKE payload
 */
static void process_qske_payload(private_ike_init_t *this, qske_payload_t *qske)
{
	if (!this->initiator)
	{
		this->qske = this->keymat->create_qske(this->keymat,
											   this->qske_mechanism);
		if (this->qske &&
			!this->qske->set_public_key(this->qske, qske->get_qske_data(qske)))
		{
			DBG1(DBG_IKE, "failed to set QSKE public key");
			this->qske_failed = TRUE;
		}
	}
	else if (this->qske)
	{
		if (this->qske->get_qske_mechanism(this->qske) != this->qske_mechanism)
		{
			DBG1(DBG_IKE, "QSKE mechanism in received payload doesn't match");
			this->qske_failed = TRUE;
		}
		else if (!this->qske->set_ciphertext(this->qske,
											 qske->get_qske_data(qske)))
		{
			DBG1(DBG_IKE, "failed to decrypt QSKE shared secret");
			this->qske_failed = TRUE;
		}
	}
}

/**
 * Process a QSKE payload during an IKE_INTERMEDIATE exchange
 */
static void process_qske_payload_intermediate(private_ike_init_t *this,
											  qske_payload_t *qske)
{
	qske_mechanism_t qske_mechanism;

	qske_mechanism = qske->get_qske_mechanism(qske);
	if (qske_mechanism == this->qske_mechanism)
	{
		process_qske_payload(this, qske);
	}
	else
	{
		DBG1(DBG_IKE, "QSKE mechanism %N differs from negotiated "
			 "mechanism %N", qske_mechanism_names, qske_mechanism,
			 qske_mechanism_names, this->qske_mechanism);
	}
}

/**
 * Read payloads from message
 */
static void process_payloads(private_ike_init_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	ke_payload_t *ke_payload = NULL;
	qske_payload_t *qske_payload = NULL;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		switch (payload->get_type(payload))
		{
			case PLV2_SECURITY_ASSOCIATION:
			{
				process_sa_payload(this, message, (sa_payload_t*)payload);
				break;
			}
			case PLV2_KEY_EXCHANGE:
			{
				ke_payload = (ke_payload_t*)payload;

				this->dh_group = ke_payload->get_dh_group_number(ke_payload);
				break;
			}
			case PLV2_QSKE:
			{
				qske_payload = (qske_payload_t*)payload;

				this->qske_mechanism = qske_payload->get_qske_mechanism(
																qske_payload);
				break;
			}
			case PLV2_NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;

				this->other_nonce = nonce_payload->get_nonce(nonce_payload);
				break;
			}
			case PLV2_NOTIFY:
			{
				notify_payload_t *notify = (notify_payload_t*)payload;

				switch (notify->get_notify_type(notify))
				{
					case FRAGMENTATION_SUPPORTED:
						this->ike_sa->enable_extension(this->ike_sa,
													   EXT_IKE_FRAGMENTATION);
						break;
					case SIGNATURE_HASH_ALGORITHMS:
						if (this->signature_authentication)
						{
							handle_supported_hash_algorithms(this, notify);
						}
						break;
					case USE_PPK:
						if (!this->old_sa)
						{
							this->ike_sa->enable_extension(this->ike_sa,
														   EXT_PPK);
						}
						break;
					case REDIRECTED_FROM:
					{
						identification_t *gateway;
						chunk_t data;

						data = notify->get_notification_data(notify);
						gateway = redirect_data_parse(data, NULL);
						if (!gateway)
						{
							DBG1(DBG_IKE, "received invalid REDIRECTED_FROM "
								 "notify, ignored");
							break;
						}
						DBG1(DBG_IKE, "client got redirected from %Y", gateway);
						gateway->destroy(gateway);
						/* fall-through */
					}
					case REDIRECT_SUPPORTED:
						if (!this->old_sa)
						{
							this->ike_sa->enable_extension(this->ike_sa,
														   EXT_IKE_REDIRECTION);
						}
						break;
					case CHILDLESS_IKEV2_SUPPORTED:
						if (this->initiator && !this->old_sa)
						{
							this->ike_sa->enable_extension(this->ike_sa,
														   EXT_IKE_CHILDLESS);
						}
						break;
					default:
						/* other notifies are handled elsewhere */
						break;
				}

			}
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (this->proposal)
	{
		this->ike_sa->set_proposal(this->ike_sa, this->proposal);
	}

	if (ke_payload && this->proposal &&
		this->proposal->has_transform(this->proposal, DIFFIE_HELLMAN_GROUP,
									  this->dh_group))
	{
		if (!this->initiator)
		{
			this->dh = this->keymat->keymat.create_dh(
								&this->keymat->keymat, this->dh_group);
		}
		else if (this->dh)
		{
			this->dh_failed = this->dh->get_dh_group(this->dh) != this->dh_group;
		}
		if (this->dh && !this->dh_failed)
		{
			this->dh_failed = !this->dh->set_other_public_value(this->dh,
								ke_payload->get_key_exchange_data(ke_payload));
		}
	}
	if (qske_payload && this->proposal && !this->dh_failed)
	{
		/* QSKE is either exchanged here or in a separate IKE_INTERMEDIATE
		 * exchange */
		if (this->proposal->has_transform(this->proposal, QSKE_MECHANISM,
										  this->qske_mechanism))
		{
			process_qske_payload(this, qske_payload);
		}
	}
}

/**
 * Get the previously selected algorithm of a specific type
 */
static uint16_t get_previous_algorithm(private_ike_init_t *this,
									   transform_type_t type)
{
	proposal_t *proposal;
	uint16_t alg;

	proposal = this->old_sa->get_proposal(this->old_sa);
	if (proposal->get_algorithm(proposal, type, &alg, NULL))
	{
		return alg;
	}
	return 0;
}

/**
 * Prepare DH implementation as initiator
 */
static bool prepare_dh(private_ike_init_t *this, ike_cfg_t *ike_cfg)
{
	if (!this->dh)
	{
		if (this->old_sa &&
			lib->settings->get_bool(lib->settings,
								"%s.prefer_previous_dh_group", TRUE, lib->ns))
		{	/* reuse the DH group we used for the old IKE_SA when rekeying */
			this->dh_group = get_previous_algorithm(this, DIFFIE_HELLMAN_GROUP);
			if (!this->dh_group)
			{	/* this shouldn't happen, but let's be safe */
				this->dh_group = ike_cfg->get_algorithm(ike_cfg,
														DIFFIE_HELLMAN_GROUP);
			}
		}
		else
		{
			this->dh_group = ike_cfg->get_algorithm(ike_cfg,
													DIFFIE_HELLMAN_GROUP);
		}
		this->dh = this->keymat->keymat.create_dh(&this->keymat->keymat,
												  this->dh_group);
		if (!this->dh)
		{
			DBG1(DBG_IKE, "configured DH group %N not supported",
				diffie_hellman_group_names, this->dh_group);
			return FALSE;
		}
	}
	else if (this->dh->get_dh_group(this->dh) != this->dh_group)
	{	/* reset DH instance if group changed (INVALID_KE_PAYLOAD) */
		this->dh->destroy(this->dh);
		this->dh = this->keymat->keymat.create_dh(&this->keymat->keymat,
												  this->dh_group);
		if (!this->dh)
		{
			DBG1(DBG_IKE, "requested DH group %N not supported",
				 diffie_hellman_group_names, this->dh_group);
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Prepare QSKE implementation as initiator
 */
static bool prepare_qske(private_ike_init_t *this, ike_cfg_t *ike_cfg)
{
	if (!this->qske)
	{
		this->qske_mechanism = ike_cfg->get_algorithm(ike_cfg, QSKE_MECHANISM);
		if (!this->qske_mechanism)
		{	/* no QSKE proposed */
			return TRUE;
		}

		if (this->old_sa &&
			lib->settings->get_bool(lib->settings,
							"%s.prefer_previous_qske_mechanism", TRUE, lib->ns))
		{	/* reuse the mechanism we used for the old IKE_SA when rekeying */
			this->qske_mechanism = get_previous_algorithm(this, QSKE_MECHANISM);
		}

		if (this->old_sa ||
			lib->settings->get_bool(lib->settings,
							"%s.send_qske_in_ike_sa_init", FALSE, lib->ns))
		{	/* only when rekeying or configured we send everything in one
			 * message and need a QSKE instance now */
			this->qske = this->keymat->create_qske(this->keymat,
												   this->qske_mechanism);
			if (!this->qske)
			{
				DBG1(DBG_IKE, "configured QSKE mechanism %N not supported",
					 qske_mechanism_names, this->qske_mechanism);
				return FALSE;
			}
		}
	}
	else if (this->qske->get_qske_mechanism(this->qske) != this->qske_mechanism)
	{	/* peer requested a different mechanism (INVALID_QSKE_PAYLOAD) */
		this->qske->destroy(this->qske);
		this->qske = this->keymat->create_qske(this->keymat,
											   this->qske_mechanism);
		if (!this->qske)
		{
			DBG1(DBG_IKE, "requested QSKE mechanism %N not supported",
				 qske_mechanism_names, this->qske_mechanism);
			return FALSE;
		}
	}
	return TRUE;
}

METHOD(task_t, build_i_intermediate, status_t,
	private_ike_init_t *this, message_t *message)
{
	qske_payload_t *qske;

	message->set_exchange_type(message, IKE_INTERMEDIATE);
	this->qske = this->keymat->create_qske(this->keymat,
										   this->qske_mechanism);
	if (!this->qske)
	{
		DBG1(DBG_IKE, "negotiated QSKE mechanism %N not supported",
			 qske_mechanism_names, this->qske_mechanism);
		return FAILED;
	}
	qske = qske_payload_create_from_qske(this->qske, TRUE);
	if (!qske)
	{
		return FAILED;
	}
	message->add_payload(message, (payload_t*)qske);
	return NEED_MORE;
}

METHOD(task_t, build_i, status_t,
	private_ike_init_t *this, message_t *message)
{
	ike_cfg_t *ike_cfg;

	ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
	DBG0(DBG_IKE, "initiating IKE_SA %s[%d] to %H",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	if (this->retry >= MAX_RETRIES)
	{
		DBG1(DBG_IKE, "giving up after %d retries", MAX_RETRIES);
		return FAILED;
	}

	if (!prepare_dh(this, ike_cfg))
	{
		return FAILED;
	}

	if (!prepare_qske(this, ike_cfg))
	{
		return FAILED;
	}

	/* generate nonce only when we are trying the first time */
	if (this->my_nonce.ptr == NULL)
	{
		if (!generate_nonce(this))
		{
			return FAILED;
		}
	}

	if (this->cookie.ptr)
	{
		message->add_notify(message, FALSE, COOKIE, this->cookie);
	}

	if (!build_payloads(this, message))
	{
		return FAILED;
	}

#ifdef ME
	{
		chunk_t connect_id = this->ike_sa->get_connect_id(this->ike_sa);
		if (connect_id.ptr)
		{
			message->add_notify(message, FALSE, ME_CONNECTID, connect_id);
		}
	}
#endif /* ME */

	return NEED_MORE;
}

METHOD(task_t, process_r_intermediate,  status_t,
	private_ike_init_t *this, message_t *message)
{
	qske_payload_t *qske;

	if (message->get_exchange_type(message) == IKE_INTERMEDIATE)
	{
		qske = (qske_payload_t*)message->get_payload(message, PLV2_QSKE);
		if (qske)
		{
			process_qske_payload_intermediate(this, qske);
		}
		else
		{
			DBG1(DBG_IKE, "QSKE payload missing in message");
		}
	}
	return NEED_MORE;
}

METHOD(task_t, process_r,  status_t,
	private_ike_init_t *this, message_t *message)
{
	DBG0(DBG_IKE, "%H is initiating an IKE_SA", message->get_source(message));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	if (!generate_nonce(this))
	{
		return FAILED;
	}

#ifdef ME
	{
		notify_payload_t *notify = message->get_notify(message, ME_CONNECTID);
		if (notify)
		{
			chunk_t connect_id = notify->get_notification_data(notify);
			DBG2(DBG_IKE, "received ME_CONNECTID %#B", &connect_id);
			charon->connect_manager->stop_checks(charon->connect_manager,
												 connect_id);
		}
	}
#endif /* ME */

	process_payloads(this, message);

	return NEED_MORE;
}

/**
 * Derive the keymat for the IKE_SA
 */
static bool derive_keys(private_ike_init_t *this, chunk_t nonce_i,
						chunk_t nonce_r)
{
	keymat_v2_t *old_keymat;
	pseudo_random_function_t prf_alg = PRF_UNDEFINED;
	chunk_t skd = chunk_empty;
	ike_sa_id_t *id;

	id = this->ike_sa->get_id(this->ike_sa);
	if (this->old_sa)
	{
		if (this->initiator)
		{
			id->set_responder_spi(id,
								  this->proposal->get_spi(this->proposal));
		}
		else
		{
			id->set_initiator_spi(id,
								  this->proposal->get_spi(this->proposal));
		}
		old_keymat = (keymat_v2_t*)this->old_sa->get_keymat(this->old_sa);
		prf_alg = old_keymat->get_skd(old_keymat, &skd);
	}
	if (!this->keymat->derive_ike_keys(this->keymat, this->proposal,
									   this->dh, this->qske, nonce_i, nonce_r,
									   id, prf_alg, skd))
	{
		return FALSE;
	}
	/* FIXME: probably should also pass QSKE implementation here */
	charon->bus->ike_keys(charon->bus, this->ike_sa, this->dh, chunk_empty,
						  nonce_i, nonce_r, this->old_sa, NULL, AUTH_NONE);
	return TRUE;
}

METHOD(task_t, post_build_r, status_t,
	private_ike_init_t *this, message_t *message)
{
	if (!derive_keys(this, this->other_nonce, this->my_nonce))
	{
		DBG1(DBG_IKE, "QSKE key derivation failed");
		return FAILED;
	}
	return SUCCESS;
}

METHOD(task_t, build_r_intermediate, status_t,
	private_ike_init_t *this, message_t *message)
{
	qske_payload_t *qske;

	if (!this->qske)
	{
		message->add_notify(message, FALSE, INVALID_SYNTAX, chunk_empty);
		return FAILED;
	}
	if (this->qske_failed)
	{
		message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}

	qske = qske_payload_create_from_qske(this->qske, FALSE);
	if (!qske)
	{
		DBG1(DBG_IKE, "failed to create QSKE payload");
		message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	message->add_payload(message, (payload_t*)qske);
	/* we do the key derivation in post_build(), otherwise the response
	 * would already be generated using the new keys */
	this->public.task.post_build = _post_build_r;
	return NEED_MORE;
}

/**
 * Check if the proposed DH group is usable as responder
 */
static bool check_dh_group(private_ike_init_t *this, message_t *message)
{
	uint16_t alg;

	if (!this->dh ||
		!this->proposal->has_transform(this->proposal, DIFFIE_HELLMAN_GROUP,
									   this->dh_group))
	{
		if (this->proposal->get_algorithm(this->proposal, DIFFIE_HELLMAN_GROUP,
										  &alg, NULL) &&
			this->dh_group != alg)
		{
			DBG1(DBG_IKE, "DH group %N unacceptable, requesting %N",
				 diffie_hellman_group_names, this->dh_group,
				 diffie_hellman_group_names, alg);
			this->dh_group = alg;
			alg = htons(alg);
			message->add_notify(message, FALSE, INVALID_KE_PAYLOAD,
								chunk_from_thing(alg));
		}
		else
		{
			DBG1(DBG_IKE, "no acceptable proposal found");
			message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		}
		return FALSE;
	}
	return TRUE;
}

/**
 * Check if the proposed QSKE mechanism is usable as responder
 */
static bool check_qske_mechanism(private_ike_init_t *this, message_t *message)
{
	uint16_t alg;

	if (this->qske_mechanism && !this->qske)
	{
		if (this->proposal->get_algorithm(this->proposal, QSKE_MECHANISM,
										  &alg, NULL) &&
			this->qske_mechanism != alg)
		{
			DBG1(DBG_IKE, "QSKE mechanism %N unacceptable, requesting %N",
				 qske_mechanism_names, this->qske_mechanism,
				 qske_mechanism_names, alg);
			this->qske_mechanism = alg;
			alg = htons(alg);
			message->add_notify(message, FALSE, INVALID_QSKE_PAYLOAD,
								chunk_from_thing(alg));
		}
		else
		{
			DBG1(DBG_IKE, "no acceptable QSKE mechanism found");
			message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN,
								chunk_empty);
		}
		return FALSE;
	}
	return TRUE;
}

METHOD(task_t, build_r, status_t,
	private_ike_init_t *this, message_t *message)
{
	identification_t *gateway;
	uint16_t alg;

	/* check if we have everything we need */
	if (this->proposal == NULL ||
		this->other_nonce.len == 0 || this->my_nonce.len == 0)
	{
		DBG1(DBG_IKE, "received proposals unacceptable");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}

	/* check if we'd have to redirect the client */
	if (!this->old_sa &&
		this->ike_sa->supports_extension(this->ike_sa, EXT_IKE_REDIRECTION) &&
		charon->redirect->redirect_on_init(charon->redirect, this->ike_sa,
										   &gateway))
	{
		chunk_t data;

		DBG1(DBG_IKE, "redirecting peer to %Y", gateway);
		data = redirect_data_create(gateway, this->other_nonce);
		message->add_notify(message, TRUE, REDIRECT, data);
		gateway->destroy(gateway);
		chunk_free(&data);
		return FAILED;
	}

	if (!check_dh_group(this, message))
	{
		/* also add an INVALID_QSKE_PAYLOAD notify if necessary */
		check_qske_mechanism(this, message);
		return FAILED;
	}

	if (!check_qske_mechanism(this, message))
	{
		return FAILED;
	}

	if (this->dh_failed)
	{
		DBG1(DBG_IKE, "applying DH public value failed");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}

	if (this->qske_failed)
	{
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}

	if (!derive_keys(this, this->other_nonce, this->my_nonce))
	{
		DBG1(DBG_IKE, "key derivation failed");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	if (!build_payloads(this, message))
	{
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	if (!this->qske &&
		this->proposal->get_algorithm(this->proposal, QSKE_MECHANISM,
									  &alg, NULL))
	{	/* use IKE_INTERMEDIATE to exchange QSKE payloads, unless we are
		 * rekeying */
		if (this->old_sa)
		{
			DBG1(DBG_IKE, "missing QSKE payload during rekeying");
			message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
			return FAILED;
		}
		this->qske_mechanism = alg;
		this->public.task.build = _build_r_intermediate;
		this->public.task.process = _process_r_intermediate;
		return NEED_MORE;
	}
	return SUCCESS;
}

/**
 * Raise alerts for received notify errors
 */
static void raise_alerts(private_ike_init_t *this, notify_type_t type)
{
	ike_cfg_t *ike_cfg;
	linked_list_t *list;

	switch (type)
	{
		case NO_PROPOSAL_CHOSEN:
			ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
			list = ike_cfg->get_proposals(ike_cfg);
			charon->bus->alert(charon->bus, ALERT_PROPOSAL_MISMATCH_IKE, list);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			break;
		default:
			break;
	}
}

METHOD(task_t, pre_process_i, status_t,
	private_ike_init_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;

	/* check for erroneous notifies */
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == PLV2_NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			notify_type_t type = notify->get_notify_type(notify);

			switch (type)
			{
				case COOKIE:
				{
					chunk_t cookie;

					cookie = notify->get_notification_data(notify);
					if (chunk_equals(cookie, this->cookie))
					{
						DBG1(DBG_IKE, "ignore response with duplicate COOKIE "
							 "notify");
						enumerator->destroy(enumerator);
						return FAILED;
					}
					break;
				}
				case REDIRECT:
				{
					identification_t *gateway;
					chunk_t data, nonce = chunk_empty;
					status_t status = SUCCESS;

					if (this->old_sa)
					{
						break;
					}
					data = notify->get_notification_data(notify);
					gateway = redirect_data_parse(data, &nonce);
					if (!gateway || !chunk_equals(nonce, this->my_nonce))
					{
						DBG1(DBG_IKE, "received invalid REDIRECT notify");
						status = FAILED;
					}
					DESTROY_IF(gateway);
					chunk_free(&nonce);
					enumerator->destroy(enumerator);
					return status;
				}
				default:
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
	return SUCCESS;
}

METHOD(task_t, post_process_i, status_t,
	private_ike_init_t *this, message_t *message)
{
	if (!derive_keys(this, this->my_nonce, this->other_nonce))
	{
		DBG1(DBG_IKE, "QSKE key derivation failed");
		return FAILED;
	}
	return SUCCESS;
}

METHOD(task_t, process_i_intermediate, status_t,
	private_ike_init_t *this, message_t *message)
{
	qske_payload_t *qske;

	qske = (qske_payload_t*)message->get_payload(message, PLV2_QSKE);
	if (qske)
	{
		process_qske_payload_intermediate(this, qske);
	}
	else
	{
		DBG1(DBG_IKE, "QSKE payload missing in message");
		return FAILED;
	}
	if (this->qske_failed)
	{
		return FAILED;
	}
	/* we do the key derivation in post_process(), otherwise calculating IntAuth
	 * would be done with the wrong keys */
	this->public.task.post_process = _post_process_i;
	return NEED_MORE;
}

/**
 * Handle an INVALID_KE_PAYLOAD notify, look for one if none given
 */
static void handle_invalid_ke(private_ike_init_t *this, message_t *message,
							  notify_payload_t *notify)
{
	diffie_hellman_group_t bad_group;
	chunk_t data;

	if (!notify || notify->get_notify_type(notify) != INVALID_KE_PAYLOAD)
	{
		notify = message->get_notify(message, INVALID_KE_PAYLOAD);
		if (!notify)
		{
			return;
		}
	}
	bad_group = this->dh_group;
	data = notify->get_notification_data(notify);
	if (data.len == sizeof(uint16_t))
	{
		this->dh_group = untoh16(data.ptr);
	}
	DBG1(DBG_IKE, "peer didn't accept DH group %N, "
		 "it requested %N", diffie_hellman_group_names,
		 bad_group, diffie_hellman_group_names, this->dh_group);
}

/**
 * Handle an INVALID_QSKE_PAYLOAD notify, look for one if none given
 */
static void handle_invalid_qske(private_ike_init_t *this, message_t *message,
								notify_payload_t *notify)
{
	qske_mechanism_t bad_mechanism;
	chunk_t data;

	if (!notify || notify->get_notify_type(notify) != INVALID_QSKE_PAYLOAD)
	{
		notify = message->get_notify(message, INVALID_QSKE_PAYLOAD);
		if (!notify)
		{
			return;
		}
	}
	bad_mechanism = this->qske_mechanism;
	data = notify->get_notification_data(notify);
	if (data.len == sizeof(uint16_t))
	{
		this->qske_mechanism = untoh16(data.ptr);
	}
	DBG1(DBG_IKE, "peer didn't accept QSKE mechanism %N, "
		 "it requested %N", qske_mechanism_names,
		 bad_mechanism, qske_mechanism_names, this->qske_mechanism);
}

METHOD(task_t, process_i, status_t,
	private_ike_init_t *this, message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	uint16_t alg;

	/* check for erroneous notifies */
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == PLV2_NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			notify_type_t type = notify->get_notify_type(notify);

			switch (type)
			{
				case INVALID_KE_PAYLOAD:
				case INVALID_QSKE_PAYLOAD:
				{
					/* check for both notifies */
					handle_invalid_ke(this, message, notify);
					handle_invalid_qske(this, message, notify);

					if (!this->old_sa)
					{	/* reset the IKE_SA if we are not rekeying */
						this->ike_sa->reset(this->ike_sa, FALSE);
					}
					enumerator->destroy(enumerator);
					this->retry++;
					return NEED_MORE;
				}
				case NAT_DETECTION_SOURCE_IP:
				case NAT_DETECTION_DESTINATION_IP:
					/* skip, handled in ike_natd_t */
					break;
				case MULTIPLE_AUTH_SUPPORTED:
					/* handled in ike_auth_t */
					break;
				case COOKIE:
				{
					chunk_free(&this->cookie);
					this->cookie = chunk_clone(notify->get_notification_data(notify));
					this->ike_sa->reset(this->ike_sa, FALSE);
					enumerator->destroy(enumerator);
					DBG2(DBG_IKE, "received %N notify", notify_type_names, type);
					this->retry++;
					return NEED_MORE;
				}
				case REDIRECT:
				{
					identification_t *gateway;
					chunk_t data, nonce = chunk_empty;
					status_t status = FAILED;

					if (this->old_sa)
					{
						DBG1(DBG_IKE, "received REDIRECT notify during rekeying"
						     ", ignored");
						break;
					}
					data = notify->get_notification_data(notify);
					gateway = redirect_data_parse(data, &nonce);
					if (this->ike_sa->handle_redirect(this->ike_sa, gateway))
					{
						status = NEED_MORE;
					}
					DESTROY_IF(gateway);
					chunk_free(&nonce);
					enumerator->destroy(enumerator);
					return status;
				}
				default:
				{
					if (type <= 16383)
					{
						DBG1(DBG_IKE, "received %N notify error",
							 notify_type_names, type);
						enumerator->destroy(enumerator);
						raise_alerts(this, type);
						return FAILED;
					}
					DBG2(DBG_IKE, "received %N notify",
						notify_type_names, type);
					break;
				}
			}
		}
	}
	enumerator->destroy(enumerator);

	process_payloads(this, message);

	/* check if we have everything */
	if (this->proposal == NULL ||
		this->other_nonce.len == 0 || this->my_nonce.len == 0)
	{
		DBG1(DBG_IKE, "peer's proposal selection invalid");
		return FAILED;
	}

	if (!this->proposal->has_transform(this->proposal, DIFFIE_HELLMAN_GROUP,
									   this->dh_group))
	{
		DBG1(DBG_IKE, "peer's DH group selection invalid");
		return FAILED;
	}

	if (this->dh_failed)
	{
		DBG1(DBG_IKE, "applying DH public value failed");
		return FAILED;
	}

	if (this->qske &&
		!this->proposal->has_transform(this->proposal, QSKE_MECHANISM,
									   this->qske_mechanism))
	{
		DBG1(DBG_IKE, "peer's QSKE mechanism selection invalid");
		return FAILED;
	}

	if (this->qske_failed)
	{
		return FAILED;
	}

	if (!derive_keys(this, this->my_nonce, this->other_nonce))
	{
		DBG1(DBG_IKE, "key derivation failed");
		return FAILED;
	}

	if (!this->qske &&
		this->proposal->get_algorithm(this->proposal, QSKE_MECHANISM,
									  &alg, NULL))
	{	/* use IKE_INTERMEDIATE to exchange QSKE payloads */
		this->qske_mechanism = alg;
		this->public.task.build = _build_i_intermediate;
		this->public.task.process = _process_i_intermediate;
		return NEED_MORE;
	}
	return SUCCESS;
}

METHOD(task_t, get_type, task_type_t,
	private_ike_init_t *this)
{
	return TASK_IKE_INIT;
}

METHOD(task_t, migrate, void,
	private_ike_init_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->proposal);
	chunk_free(&this->other_nonce);

	this->ike_sa = ike_sa;
	this->keymat = (keymat_v2_t*)ike_sa->get_keymat(ike_sa);
	this->proposal = NULL;
	this->dh_failed = FALSE;
	this->qske_failed = FALSE;
}

METHOD(task_t, destroy, void,
	private_ike_init_t *this)
{
	DESTROY_IF(this->dh);
	DESTROY_IF(this->qske);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->nonceg);
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	chunk_free(&this->cookie);
	free(this);
}

METHOD(ike_init_t, get_lower_nonce, chunk_t,
	private_ike_init_t *this)
{
	if (memcmp(this->my_nonce.ptr, this->other_nonce.ptr,
			   min(this->my_nonce.len, this->other_nonce.len)) < 0)
	{
		return this->my_nonce;
	}
	else
	{
		return this->other_nonce;
	}
}

/*
 * Described in header.
 */
ike_init_t *ike_init_create(ike_sa_t *ike_sa, bool initiator, ike_sa_t *old_sa)
{
	private_ike_init_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
			.get_lower_nonce = _get_lower_nonce,
		},
		.ike_sa = ike_sa,
		.initiator = initiator,
		.dh_group = MODP_NONE,
		.keymat = (keymat_v2_t*)ike_sa->get_keymat(ike_sa),
		.old_sa = old_sa,
		.signature_authentication = lib->settings->get_bool(lib->settings,
								"%s.signature_authentication", TRUE, lib->ns),
		.follow_redirects = lib->settings->get_bool(lib->settings,
								"%s.follow_redirects", TRUE, lib->ns),
	);
	this->nonceg = this->keymat->keymat.create_nonce_gen(&this->keymat->keymat);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
		this->public.task.pre_process = _pre_process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}
	return &this->public;
}
