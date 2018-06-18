/*
 * Copyright (C) 2018 Andreas Steffen
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

#include "qske_mechanism.h"

ENUM(qske_mechanism_names, QSKE_NONE, QSKE_FRODO,
	"QSKE_NONE",
	"QSKE_NEWHOPE",
	"QSKE_NEWHOPE_L1",
	"QSKE_NEWHOPE_L5",
	"QSKE_FRODO_AES_L1",
	"QSKE_FRODO_AES_L3",
	"QSKE_FRODO_SHAKE_L1",
	"QSKE_FRODO_SHAKE_L3",
	"QSKE_KYBER_L1",
	"QSKE_KYBER_L3",
	"QSKE_KYBER_L5",
	"QSKE_BIKE1_L1",
	"QSKE_BIKE1_L3",
	"QSKE_BIKE1_L5",
	"QSKE_BIKE2_L1",
	"QSKE_BIKE2_L3",
	"QSKE_BIKE2_L5",
	"QSKE_BIKE3_L1",
	"QSKE_BIKE3_L3",
	"QSKE_BIKE3_L5",
	"QSKE_SIKE_L1",
	"QSKE_SIKE_L3",
	"QSKE_SABER_L1",
	"QSKE_SABER_L3",
	"QSKE_SABER_L5",
	"QSKE_LIMA_2P_L3",
	"QSKE_LIMA_2P_L5",
	"QSKE_LIMA_SP_L1",
	"QSKE_LIMA_SP_L2",
	"QSKE_LIMA_SP_L3",
	"QSKE_LIMA_SP_L5"
);
