/*
 * Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved. This
 * program and the accompanying materials are licensed and made available
 * under the terms and conditions of the 2-Clause BSD License which
 * accompanies this distribution.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * https://github.com/tianocore/edk2-staging (edk2-staging repo of tianocore),
 * the ImageAuthentication.h file under it, and here's the copyright and license.
 *
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 * Copyright 2022, 2023, 2024, 2025 IBM Corp.
 */

#ifndef __PLATFORM_KEYSTORE_H__
#define __PLATFORM_KEYSTORE_H__

#include <grub/symbol.h>
#include <grub/mm.h>
#include <grub/types.h>

#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#define GRUB_MAX_HASH_SIZE 64

/* Secure Boot Mode. */
#define SB_DISABLED        0
#define SB_ENFORCED        2

/*
 * It is derived from EFI_SIGNATURE_DATA
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI signature database (ESD).*/
struct grub_esd
{
  /*
   * An identifier which identifies the agent which added
   * the signature to the list.
   */
  grub_packed_guid_t signature_owner;
  /* The format of the signature is defined by the SignatureType.*/
  grub_uint8_t signature_data[];
} GRUB_PACKED;

typedef struct grub_esd grub_esd_t;

/*
 * It is derived from EFI_SIGNATURE_LIST
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 *
 * The structure of an EFI signature list (ESL).*/
struct grub_esl
{
  /* Type of the signature. GUID signature types are defined in below.*/
  grub_packed_guid_t signature_type;
  /* Total size of the signature list, including this header.*/
  grub_uint32_t signature_list_size;
  /*
   * Size of the signature header which precedes
   * the array of signatures.
   */
  grub_uint32_t signature_header_size;
  /* Size of each signature.*/
  grub_uint32_t signature_size;
} GRUB_PACKED;

typedef struct grub_esl grub_esl_t;

/* The structure of a PKS signature data.*/
struct grub_pks_sd
{
  grub_packed_guid_t guid; /* Signature type. */
  grub_uint8_t *data;      /* Signature data. */
  grub_size_t data_size;   /* Size of signature data. */
} GRUB_PACKED;

typedef struct grub_pks_sd grub_pks_sd_t;

/* The structure of a PKS.*/
struct grub_pks
{
  grub_pks_sd_t *db;        /* Signature database. */
  grub_pks_sd_t *dbx;       /* Forbidden signature database. */
  grub_size_t db_entries;   /* Size of signature database. */
  grub_size_t dbx_entries;  /* Size of forbidden signature database. */
  bool use_static_keys;     /* Flag to indicate use of static keys. */
} GRUB_PACKED;

typedef struct grub_pks grub_pks_t;

/* Initialization of the Platform Keystore. */
extern grub_err_t
grub_pks_keystore_init (void);

/* Free allocated memory. */
extern void
EXPORT_FUNC (grub_pks_free_keystore) (void);

extern grub_uint8_t EXPORT_VAR (grub_pks_use_keystore);
extern grub_pks_t EXPORT_VAR (grub_pks_keystore);

#endif
