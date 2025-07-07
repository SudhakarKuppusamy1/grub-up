/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2021, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022, 2025 IBM Corporation
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/command.h>
#include <grub/crypto.h>
#include <grub/pkcs1_v15.h>
#include <grub/i18n.h>
#include <grub/gcrypt/gcrypt.h>
#include <grub/kernel.h>
#include <grub/extcmd.h>
#include <grub/verify.h>
#include <libtasn1.h>
#include <grub/env.h>
#include <grub/lockdown.h>
#include <grub/efi/pks.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>
#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Public key type. */
#define GRUB_PKEY_ID_PKCS7  2
/* GUID size. */
#define GRUB_GUID_SIZE      (sizeof (grub_packed_guid_t))

/* Appended signature magic string. */
static const char magic[] = "~Module signature appended~\n";

/*
 * This structure is extracted from scripts/sign-file.c in the linux kernel
 * source. It was licensed as LGPLv2.1+, which is GPLv3+ compatible.
 */
struct module_signature
{
  grub_uint8_t algo;       /* Public-key crypto algorithm [0]. */
  grub_uint8_t hash;       /* Digest algorithm [0]. */
  grub_uint8_t id_type;    /* Key identifier type [GRUB_PKEY_ID_PKCS7]. */
  grub_uint8_t signer_len; /* Length of signer's name [0]. */
  grub_uint8_t key_id_len; /* Length of key identifier [0]. */
  grub_uint8_t __pad[3];
  grub_uint32_t sig_len;   /* Length of signature data. */
} GRUB_PACKED;

/* This represents an entire, parsed, appended signature. */
struct grub_appended_signature
{
  grub_size_t signature_len;            /* Length of PKCS#7 data + metadata + magic. */
  struct module_signature sig_metadata; /* Module signature metadata. */
  struct pkcs7_signedData pkcs7;        /* Parsed PKCS#7 data. */
};

/* This represents a db/dbx list. */
struct grub_database
{
  struct x509_certificate *certs; /* Certificates. */
  grub_size_t cert_entries;       /* Number of certificates. */
  grub_uint8_t **signatures;      /* Certificate/binary hashes. */
  grub_size_t *signature_size;    /* Size of certificate/binary hashes. */
  grub_size_t signature_entries;  /* Number of certificate/binary hashes. */
};

/* The db list */
struct grub_database db = {.certs = NULL, .cert_entries = 0, .signatures = NULL,
                           .signature_size = NULL, .signature_entries = 0};

/* The dbx list */
struct grub_database dbx = {.certs = NULL, .cert_entries = 0, .signatures = NULL,
                            .signature_size = NULL, .signature_entries = 0};

/* Free db list memory */
static void
free_db_list (void);
/* Free dbx list memory */
static void
free_dbx_list (void);

static enum
{
  CHECK_SIGS_NO = 0,
  CHECK_SIGS_ENFORCE = 1,
  CHECK_SIGS_FORCED = 2
} check_sigs = CHECK_SIGS_NO;

/*
 * GUID can be used to determine the hashing function and
 * generate the hash using determined hashing function.
 */
static grub_err_t
get_hash (const grub_packed_guid_t *guid, const grub_uint8_t *data, const grub_size_t data_size,
          grub_uint8_t *hash, grub_size_t *hash_size)
{
  gcry_md_spec_t *hash_func = NULL;

  if (guid == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "GUID is empty.");

  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha256;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha384;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "unsupported GUID for hash.");

  grub_memset (hash, 0, GRUB_MAX_HASH_SIZE);
  grub_crypto_hash (hash_func, hash, data, data_size);
  *hash_size =  hash_func->mdlen;

  return GRUB_ERR_NONE;
}

/* Add the certificate/binary hash into the db/dbx list. */
static grub_err_t
add_hash (const grub_uint8_t **data, const grub_size_t data_size,
          grub_uint8_t ***signature_list, grub_size_t **signature_size_list,
          grub_size_t *signature_list_entries)
{
  grub_uint8_t **signatures = *signature_list;
  grub_size_t *signature_size = *signature_size_list;
  grub_size_t signature_entries = *signature_list_entries;

  if (*data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate/binary-hash data or size is empty.");

  signatures = grub_realloc (signatures, sizeof (grub_uint8_t *) * (signature_entries + 1));
  signature_size = grub_realloc (signature_size,
                                 sizeof (grub_size_t) * (signature_entries + 1));

  if (signatures == NULL || signature_size == NULL)
    {
      /*
       * Allocated memory will be freed by
       * free_db_list/free_dbx_list.
       */
      if (signatures != NULL)
        {
          *signature_list = signatures;
          *signature_list_entries = signature_entries + 1;
        }

      if (signature_size != NULL)
        *signature_size_list = signature_size;

      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory.");
    }

  signatures[signature_entries] = (grub_uint8_t *) *data;
  signature_size[signature_entries] = data_size;
  signature_entries++;
  *data = NULL;

  *signature_list = signatures;
  *signature_size_list = signature_size;
  *signature_list_entries = signature_entries;

  return GRUB_ERR_NONE;
}

static bool
is_x509 (const grub_packed_guid_t *guid)
{
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_GUID, GRUB_GUID_SIZE) == 0)
    return true;

  return false;
}

static bool
is_cert_match (const struct x509_certificate *distrusted_cert,
               const struct x509_certificate *db_cert)
{
  if (grub_memcmp (distrusted_cert->subject, db_cert->subject, db_cert->subject_len) == 0
      && grub_memcmp (distrusted_cert->serial, db_cert->serial, db_cert->serial_len) == 0
      && grub_memcmp (distrusted_cert->mpis[0], db_cert->mpis[0], sizeof (db_cert->mpis[0])) == 0
      && grub_memcmp (distrusted_cert->mpis[1], db_cert->mpis[1], sizeof (db_cert->mpis[1])) == 0)
    return true;

  return false;
}


/* Check the certificate presence in the platform keystore dbx list. */
static grub_err_t
is_dbx_cert (const struct x509_certificate *db_cert)
{
  grub_err_t rc;
  grub_size_t i;
  struct x509_certificate *distrusted_cert;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL)
        continue;

      if (is_x509 (&grub_pks_keystore.dbx[i].guid) == true)
        {
          distrusted_cert = grub_zalloc (sizeof (struct x509_certificate));
          if (distrusted_cert == NULL)
            return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory.");

          rc = parse_x509_certificate (grub_pks_keystore.dbx[i].data,
                                       grub_pks_keystore.dbx[i].data_size, distrusted_cert);
          if (rc != GRUB_ERR_NONE)
            {
              grub_free (distrusted_cert);
              continue;
            }

          if (is_cert_match (distrusted_cert, db_cert) == true)
            {
              grub_printf ("Warning: a trusted certificate CN='%s' is ignored "
                           "because it is on the dbx list.\n", db_cert->subject);
              grub_free (grub_pks_keystore.dbx[i].data);
              grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof (grub_pks_sd_t));
              certificate_release (distrusted_cert);
              grub_free (distrusted_cert);
              return GRUB_ERR_ACCESS_DENIED;
            }

          certificate_release (distrusted_cert);
          grub_free (distrusted_cert);
        }
    }

  return GRUB_ERR_NONE;
}

/* Add the certificate into the db/dbx list */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 struct grub_database *database, const bool is_db)
{
  struct x509_certificate *cert;
  grub_err_t rc;
  grub_size_t cert_entries = database->cert_entries;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is empty.");

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory.");

  rc = parse_x509_certificate (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "skipped %s certificate (%d)\n",
                    (is_db == true ? "trusted":"distrusted"), (int) rc);
      grub_free (cert);
      return rc;
    }

  if (is_db == true)
    {
      rc = is_dbx_cert (cert);
      if (rc != GRUB_ERR_NONE)
        {
          certificate_release (cert);
          grub_free (cert);
          return rc;
        }
    }

  grub_dprintf ("appendedsig", "add a %s certificate CN='%s'\n",
                (is_db == true ? "trusted":"distrusted"), cert->subject);

  cert_entries++;
  cert->next = database->certs;
  database->certs = cert;
  database->cert_entries = cert_entries;

  return rc;
}

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                   const char *val __attribute__ ((unused)))
{
  if (check_sigs == CHECK_SIGS_FORCED)
    return "forced";
  else if (check_sigs == CHECK_SIGS_ENFORCE)
    return "enforce";

  return "no";
}

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /* Do not allow the value to be changed if set to forced. */
  if (check_sigs == CHECK_SIGS_FORCED)
    {
      ret = grub_strdup ("forced");
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string forced.");

      return ret;
    }

  if ((*val == '2') || (*val == 'f'))
    check_sigs = CHECK_SIGS_FORCED;
  else if ((*val == '1') || (*val == 'e'))
    check_sigs = CHECK_SIGS_ENFORCE;
  else if ((*val == '0') || (*val == 'n'))
    check_sigs = CHECK_SIGS_NO;

  ret = grub_strdup (grub_env_read_sec (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string %s",
                grub_env_read_sec (NULL, NULL));

  return ret;
}

static grub_err_t
file_read_all (grub_file_t file, grub_uint8_t **buf, grub_size_t *len)
{
  grub_off_t full_file_size;
  grub_size_t file_size, total_read_size = 0;
  grub_ssize_t read_size;

  full_file_size = grub_file_size (file);
  if (full_file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "cannot read a file of unknown size into a buffer.");

  if (full_file_size > GRUB_SIZE_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "file is too large to read: %" PRIuGRUB_UINT64_T " bytes.",
                       full_file_size);

  file_size = (grub_size_t) full_file_size;
  *buf = grub_malloc (file_size);
  if (*buf == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate file data buffer size %" PRIuGRUB_SIZE,
                       file_size);

  while (total_read_size < file_size)
    {
      read_size = grub_file_read (file, *buf + total_read_size, file_size - total_read_size);
      if (read_size < 0)
        {
          grub_free (*buf);
          return grub_errno;
        }
      else if (read_size == 0)
        {
          grub_free (*buf);
          return grub_error (GRUB_ERR_IO,
                             "could not read full file size "
                             "(%" PRIuGRUB_SIZE "), only %" PRIuGRUB_SIZE " bytes read.",
                             file_size, total_read_size);
        }

      total_read_size += read_size;
    }

  *len = file_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
read_cert_from_file (grub_file_t f, struct x509_certificate *certificate)
{
  grub_err_t err;
  grub_uint8_t *buf;
  grub_size_t file_size;

  err = file_read_all (f, &buf, &file_size);
  if (err != GRUB_ERR_NONE)
    return err;

  err = parse_x509_certificate (buf, file_size, certificate);
  grub_free (buf);

  return err;
}

static grub_err_t
extract_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize,
                            struct grub_appended_signature *sig)
{
  grub_size_t pkcs7_size;
  grub_size_t remaining_len;
  const grub_uint8_t *appsigdata = buf + bufsize - grub_strlen (magic);

  if (bufsize < grub_strlen (magic))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature magic.");

  if (grub_strncmp ((const char *) appsigdata, magic, sizeof (magic) - 1))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "missing or invalid signature magic.");

  remaining_len = bufsize - grub_strlen (magic);

  if (remaining_len < sizeof (struct module_signature))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature metadata.");

  appsigdata -= sizeof (struct module_signature);
  /* Extract the metadata. */
  grub_memcpy (&(sig->sig_metadata), appsigdata, sizeof (struct module_signature));
  remaining_len -= sizeof (struct module_signature);

  if (sig->sig_metadata.id_type != GRUB_PKEY_ID_PKCS7)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "wrong signature type.");

  pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  if (pkcs7_size > remaining_len)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for PKCS#7 message.");

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", pkcs7_size);

  sig->signature_len = grub_strlen (magic) + sizeof (struct module_signature) + pkcs7_size;
  /* Rewind pointer and parse pkcs7 data. */
  appsigdata -= pkcs7_size;

  return parse_pkcs7_signedData (appsigdata, pkcs7_size, &sig->pkcs7);
}

static grub_err_t
grub_verify_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize)
{
  grub_err_t err = GRUB_ERR_NONE;
  grub_size_t datasize;
  void *context;
  unsigned char *hash;
  gcry_mpi_t hashmpi;
  gcry_err_code_t rc;
  struct x509_certificate *pk;
  struct grub_appended_signature sig;
  struct pkcs7_signerInfo *si;
  int i;

  if (!db.cert_entries)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "no trusted keys to verify against.");

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  datasize = bufsize - sig.signature_len;

  for (i = 0; i < sig.pkcs7.signerInfo_count; i++)
    {
      /*
       * This could be optimised in a couple of ways:
       * - we could only compute hashes once per hash type.
       * - we could track signer information and only verify where IDs match.
       * For now we do the naive O(trusted keys * pkcs7 signers) approach.
       */
      si = &sig.pkcs7.signerInfos[i];
      context = grub_zalloc (si->hash->contextsize);
      if (context == NULL)
        return grub_errno;

      si->hash->init (context);
      si->hash->write (context, buf, datasize);
      si->hash->final (context);
      hash = si->hash->read (context);

      grub_dprintf ("appendedsig", "data size %" PRIxGRUB_SIZE ", signer %d hash %02x%02x%02x%02x...\n",
                    datasize, i, hash[0], hash[1], hash[2], hash[3]);

      err = GRUB_ERR_BAD_SIGNATURE;
      for (pk = db.certs; pk != NULL; pk = pk->next)
        {
          rc = grub_crypto_rsa_pad (&hashmpi, hash, si->hash, pk->mpis[0]);
          if (rc != GPG_ERR_NO_ERROR)
            {
              err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                                "error padding hash for RSA verification: %d", (int) rc);
              grub_free (context);
              goto cleanup;
            }

          rc = grub_crypto_pk_rsa->verify (0, hashmpi, &si->sig_mpi, pk->mpis, NULL, NULL);
          gcry_mpi_release (hashmpi);
          if (rc == GPG_ERR_NO_ERROR)
            {
              grub_dprintf ("appendedsig", "verify signer %d with key '%s' succeeded.\n",
                            i, pk->subject);
              err = GRUB_ERR_NONE;
              break;
            }

          grub_dprintf ("appendedsig", "verify signer %d with key '%s' failed with %d\n",
                        i, pk->subject, (int) rc);
        }

      grub_free (context);
      if (err == GRUB_ERR_NONE)
        break;
    }

  /* If we didn't verify, provide a neat message. */
  if (err != GRUB_ERR_NONE)
    err = grub_error (GRUB_ERR_BAD_SIGNATURE,
                      "failed to verify signature against a trusted key.");

 cleanup:
  pkcs7_signedData_release (&sig.pkcs7);

  return err;
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t signed_file;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t *data;
  grub_size_t file_size;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "one argument expected.");

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  signed_file = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (signed_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file.", args[0]);

  err = file_read_all (signed_file, &data, &file_size);
  if (err == GRUB_ERR_NONE)
    err = grub_verify_appended_signature (data, file_size);

  grub_file_close (signed_file);
  grub_free (data);

  return err;
}

static grub_err_t
grub_cmd_dbx (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  unsigned long cert_num, i = 0;
  const char *end;
  struct x509_certificate *cert, *prev_cert;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "one argument expected.");

  cert_num = grub_strtoul (args[0], &end, 10);
  if (*(args[0]) == '\0' || *end != '\0')
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "non-numeric or certificate number is invalid %s", args[0]);
  else if (cert_num == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate numbers start at 1.");

  for (cert = prev_cert = db.certs; cert != NULL; cert = cert->next)
    {
      if (cert_num == 1) /* Match with first certificate in the db. */
        {
          db.certs = cert->next;
          break;
        }
      else if (cert_num == i)
        {
          prev_cert->next = cert->next;
          break;
        }

      prev_cert = cert;
      i++;
    }

  if (cert != NULL)
    {
      db.cert_entries--;
      certificate_release (cert);
      grub_free (cert);
      return GRUB_ERR_NONE;
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT,
                     "not found certificate number %lu in the db.", cert_num);
}

static grub_err_t
grub_cmd_db (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t certf;
  struct x509_certificate *cert = NULL;
  grub_err_t err;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "one argument expected.");

  certf = grub_file_open (args[0], GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (certf == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file.", args[0]);

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not allocate memory for certificate.");

  err = read_cert_from_file (certf, cert);
  grub_file_close (certf);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert);
      return err;
    }

  grub_dprintf ("appendedsig", "loaded certificate with CN: %s\n", cert->subject);

  cert->next = db.certs;
  db.certs = cert;
  db.cert_entries++;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
               char **args __attribute__ ((unused)))
{
  struct x509_certificate *cert;
  int cert_num = 1;
  grub_size_t i;

  for (cert = db.certs; cert != NULL; cert = cert->next)
    {
      grub_printf ("Certificate %d:\n", cert_num);
      grub_printf ("\tSerial: ");

      for (i = 0; i < cert->serial_len - 1; i++)
        grub_printf ("%02x:", cert->serial[i]);

      grub_printf ("%02x\n", cert->serial[cert->serial_len - 1]);
      grub_printf ("\tCN: %s\n\n", cert->subject);
      cert_num++;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
appendedsig_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
                  void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  if (check_sigs == CHECK_SIGS_NO)
    {
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }

  switch (type & GRUB_FILE_TYPE_MASK)
    {
      case GRUB_FILE_TYPE_CERTIFICATE_TRUST:
        /*
         * This is a certificate to add to trusted keychain.
         *
         * This needs to be verified or blocked. Ideally we'd write an x509
         * verifier, but we lack the hubris required to take this on. Instead,
         * require that it have an appended signature.
         */
      case GRUB_FILE_TYPE_LINUX_KERNEL:
      case GRUB_FILE_TYPE_GRUB_MODULE:
        /*
         * Appended signatures are only defined for ELF binaries.
         * Out of an abundance of caution, we only verify Linux kernels and
         * GRUB modules at this point.
         */
        *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
        return GRUB_ERR_NONE;

      case GRUB_FILE_TYPE_ACPI_TABLE:
      case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
        /*
         * It is possible to use appended signature verification without
         * lockdown - like the PGP verifier. When combined with an embedded
         * config file in a signed GRUB binary, this could still be a meaningful
         * secure-boot chain - so long as it isn't subverted by something like a
         * rouge ACPI table or DT image. Defer them explicitly.
         */
        *flags = GRUB_VERIFY_FLAGS_DEFER_AUTH;
        return GRUB_ERR_NONE;

      default:
        *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
        return GRUB_ERR_NONE;
    }
}

static grub_err_t
appendedsig_write (void *ctxt __attribute__ ((unused)), void *buf, grub_size_t size)
{
  return grub_verify_appended_signature (buf, size);
}

struct grub_file_verifier grub_appendedsig_verifier = {
  .name = "appendedsig",
  .init = appendedsig_init,
  .write = appendedsig_write,
};

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
  return len;
}

/* Filesystem descriptor. */
static struct grub_fs pseudo_fs = {
  .name = "pseudo",
  .fs_read = pseudo_read
};

static grub_command_t cmd_verify, cmd_list, cmd_dbx, cmd_db;

/* Check the certificate hash presence in the dbx list. */
static bool
is_dbx_cert_hash (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc;
  grub_size_t i, cert_hash_size = 0;
  grub_uint8_t cert_hash[GRUB_MAX_HASH_SIZE] = { 0 };

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      rc = get_hash (&grub_pks_keystore.dbx[i].guid, data, data_size,
                     cert_hash, &cert_hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (cert_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, cert_hash, cert_hash_size) == 0)
        {
          grub_printf ("Warning: a trusted certificate (%02x%02x%02x%02x) is ignored "
                       "because this certificate hash is on the dbx list.\n",
                       cert_hash[0], cert_hash[1], cert_hash[2], cert_hash[3]);
          grub_free (grub_pks_keystore.dbx[i].data);
          grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof (grub_pks_keystore.dbx[i]));
          return true;
        }
    }

  return false;
}

/* Check the binary hash presence in the dbx list. */
static bool
is_dbx_binary_hash (const grub_uint8_t *binary_hash, const grub_size_t binary_hash_size)
{
  grub_size_t i;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      if (binary_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, binary_hash, binary_hash_size) == 0)
        {
          grub_printf ("Warning: a trusted binary hash (%02x%02x%02x%02x) is ignored"
                       " because it is on the dbx list.\n", binary_hash[0], binary_hash[1],
                       binary_hash[2], binary_hash[3]);
          grub_free (grub_pks_keystore.dbx[i].data);
          grub_memset (&grub_pks_keystore.dbx[i], 0, sizeof(grub_pks_keystore.dbx[i]));
          return true;
        }
    }

  return false;
}

/* Add the binary hash to the db list if it does not exist in the dbx list. */
static grub_err_t
add_db_binary_hash (const grub_uint8_t **data, const grub_size_t data_size)
{
  if (*data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "trusted binary hash data or size is empty.");

  if (is_dbx_binary_hash (*data, data_size) == false)
    return add_hash (data, data_size, &db.signatures, &db.signature_size,
                     &db.signature_entries);

  return GRUB_ERR_BAD_SIGNATURE;
}

static bool
is_hash (const grub_packed_guid_t *guid)
{
  /* GUID type of the binary hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_GUID_SIZE) == 0)
    return true;

  /* GUID type of the certificate hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_GUID_SIZE) == 0)
    return true;

  return false;
}

/* Add the X.509 certificates/binary hash to the db list. */
static grub_err_t
create_db_list (void)
{
  grub_err_t rc;
  grub_size_t i;

  for (i = 0; i < grub_pks_keystore.db_entries; i++)
    {
      if (is_hash (&grub_pks_keystore.db[i].guid) == true)
        {
          rc = add_db_binary_hash ((const grub_uint8_t **) &grub_pks_keystore.db[i].data,
                                   grub_pks_keystore.db[i].data_size);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_x509 (&grub_pks_keystore.db[i].guid) == true)
        {
          if (is_dbx_cert_hash (grub_pks_keystore.db[i].data,
                                grub_pks_keystore.db[i].data_size) == true)
            continue;

          rc = add_certificate (grub_pks_keystore.db[i].data,
                                grub_pks_keystore.db[i].data_size, &db, true);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%" PRIuGRUB_SIZE ")\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/* Add the certificates and certificate/binary hash to the dbx list. */
static grub_err_t
create_dbx_list (void)
{
  grub_err_t rc;
  grub_size_t i;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data != NULL ||
          grub_pks_keystore.dbx[i].data_size > 0)
        {
          if (is_x509 (&grub_pks_keystore.dbx[i].guid) == true)
            {
              rc = add_certificate (grub_pks_keystore.dbx[i].data,
                                    grub_pks_keystore.dbx[i].data_size, &dbx, false);
              if (rc == GRUB_ERR_OUT_OF_MEMORY)
                return rc;
            }
          else if (is_hash (&grub_pks_keystore.dbx[i].guid) == true)
            {
              rc = add_hash ((const grub_uint8_t **) &grub_pks_keystore.dbx[i].data,
                             grub_pks_keystore.dbx[i].data_size,
                             &dbx.signatures, &dbx.signature_size,
                             &dbx.signature_entries);
              if (rc != GRUB_ERR_NONE)
                return rc;
            }
          else
            grub_dprintf ("appendedsig", "unsupported signature data type and "
                          "skipped (%" PRIuGRUB_SIZE ")\n", i + 1);
        }
    }

  return GRUB_ERR_NONE;
}

/*
 * Extract the x509 certificates from the ELF note header,
 * parse it, and add it to the db list.
 */
static grub_err_t
build_static_db_list (const struct grub_module_header *header)
{
  grub_err_t err;
  struct grub_file pseudo_file;
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
  pseudo_file.fs = &pseudo_fs;
  pseudo_file.size = header->size - sizeof (struct grub_module_header);
  pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

  grub_dprintf ("appendedsig", "found an x509 key, size=%" PRIuGRUB_UINT64_T "\n",
                pseudo_file.size);

  err = file_read_all (&pseudo_file, &cert_data, &cert_data_size);
  if (err != GRUB_ERR_NONE)
    return err;

  err = add_certificate (cert_data, cert_data_size, &db, true);
  grub_free (cert_data);

  return err;
}

/* Free db list memory */
static void
free_db_list (void)
{
  struct x509_certificate *cert;
  grub_size_t i = 0;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < db.signature_entries; i++)
    grub_free (db.signatures[i]);

  grub_free (db.signatures);
  grub_free (db.signature_size);
  grub_memset (&db, 0, sizeof (db));
}

/* Free dbx list memory */
static void
free_dbx_list (void)
{
  struct x509_certificate *cert;
  grub_size_t i = 0;

  while (dbx.certs != NULL)
    {
      cert = dbx.certs;
      dbx.certs = dbx.certs->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < dbx.signature_entries; i++)
    grub_free (dbx.signatures[i]);

  grub_free (dbx.signatures);
  grub_free (dbx.signature_size);
  grub_memset (&dbx, 0, sizeof (dbx));
}

GRUB_MOD_INIT (appendedsig)
{
  int rc;
  struct grub_module_header *header;

  /* If in lockdown, immediately enter forced mode. */
  if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    check_sigs = CHECK_SIGS_FORCED;

  grub_register_variable_hook ("check_appended_signatures", grub_env_read_sec, grub_env_write_sec);
  grub_env_export ("check_appended_signatures");

  rc = asn1_init ();
  if (rc)
    grub_fatal ("error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  if (!grub_pks_use_keystore && check_sigs == CHECK_SIGS_FORCED)
    {
      FOR_MODULES (header)
        {
          /* Not an ELF module, skip.  */
          if (header->type != OBJ_TYPE_X509_PUBKEY)
            continue;

          rc = build_static_db_list (header);
          if (rc != GRUB_ERR_NONE)
            {
              free_db_list ();
              grub_error (rc, "static db list creation failed.");
            }
          else
            grub_dprintf ("appendedsig", "the db list now has %" PRIuGRUB_SIZE " static keys.\n",
                          db.cert_entries);
        }
    }
  else if (grub_pks_use_keystore && check_sigs == CHECK_SIGS_FORCED)
    {
      rc = create_db_list ();
      if (rc != GRUB_ERR_NONE)
        {
          free_db_list ();
          grub_error (rc, "db list creation failed.");
        }
      else
        {
          rc = create_dbx_list ();
          if (rc != GRUB_ERR_NONE)
            {
              free_db_list ();
              free_dbx_list ();
              grub_error (rc, "dbx list creation failed.");
            }
          else
            grub_dprintf ("appendedsig", "the db list now has %" PRIuGRUB_SIZE " keys.\n"
                          "the dbx list now has %" PRIuGRUB_SIZE " keys.\n",
                          db.signature_entries + db.cert_entries, dbx.signature_entries);
        }
      grub_pks_free_keystore ();
    }

  cmd_db = grub_register_command ("append_add_db_cert", grub_cmd_db, N_("X509_CERTIFICATE"),
                                  N_("Add trusted X509_CERTIFICATE to the db"));
  cmd_list = grub_register_command ("append_list_db", grub_cmd_list, 0,
                                    N_("Show the list of trusted X.509 certificates from the db"));
  cmd_verify = grub_register_command ("append_verify", grub_cmd_verify_signature, N_("FILE"),
                                      N_("Verify FILE against the trusted X.509 certificates in the db"));
  cmd_dbx = grub_register_command ("append_rm_dbx_cert", grub_cmd_dbx, N_("CERT_NUMBER"),
                                   N_("Remove CERT_NUMBER (as listed by append_list_db) from the db"));

  grub_verifier_register (&grub_appendedsig_verifier);
  grub_dl_set_persistent (mod);
}

GRUB_MOD_FINI (appendedsig)
{
  /*
   * grub_dl_set_persistent should prevent this from actually running, but
   * it does still run under emu.
   */
  grub_verifier_unregister (&grub_appendedsig_verifier);
  grub_unregister_command (cmd_verify);
  grub_unregister_command (cmd_list);
  grub_unregister_command (cmd_db);
  grub_unregister_command (cmd_dbx);
}
