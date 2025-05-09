/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "otautil/verifier.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <vector>

#include <android-base/logging.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <ziparchive/zip_archive.h>

#include "otautil/print_sha1.h"
#include "private/asn1_decoder.h"

/*
 * Simple version of PKCS#7 SignedData extraction. This extracts the
 * signature OCTET STRING to be used for signature verification.
 *
 * For full details, see http://www.ietf.org/rfc/rfc3852.txt
 *
 * The PKCS#7 structure looks like:
 *
 *   SEQUENCE (ContentInfo)
 *     OID (ContentType)
 *     [0] (content)
 *       SEQUENCE (SignedData)
 *         INTEGER (version CMSVersion)
 *         SET (DigestAlgorithmIdentifiers)
 *         SEQUENCE (EncapsulatedContentInfo)
 *         [0] (CertificateSet OPTIONAL)
 *         [1] (RevocationInfoChoices OPTIONAL)
 *         SET (SignerInfos)
 *           SEQUENCE (SignerInfo)
 *             INTEGER (CMSVersion)
 *             SEQUENCE (SignerIdentifier)
 *             SEQUENCE (DigestAlgorithmIdentifier)
 *             SEQUENCE (SignatureAlgorithmIdentifier)
 *             OCTET STRING (SignatureValue)
 */
[[maybe_unused]] static bool read_pkcs7(const uint8_t* pkcs7_der, size_t pkcs7_der_len,
                       std::vector<uint8_t>* sig_der) {
  CHECK(sig_der != nullptr);
  sig_der->clear();

  asn1_context ctx(pkcs7_der, pkcs7_der_len);

  std::unique_ptr<asn1_context> pkcs7_seq(ctx.asn1_sequence_get());
  if (pkcs7_seq == nullptr || !pkcs7_seq->asn1_sequence_next()) {
    return false;
  }

  std::unique_ptr<asn1_context> signed_data_app(pkcs7_seq->asn1_constructed_get());
  if (signed_data_app == nullptr) {
    return false;
  }

  std::unique_ptr<asn1_context> signed_data_seq(signed_data_app->asn1_sequence_get());
  if (signed_data_seq == nullptr || !signed_data_seq->asn1_sequence_next() ||
      !signed_data_seq->asn1_sequence_next() || !signed_data_seq->asn1_sequence_next() ||
      !signed_data_seq->asn1_constructed_skip_all()) {
    return false;
  }

  std::unique_ptr<asn1_context> sig_set(signed_data_seq->asn1_set_get());
  if (sig_set == nullptr) {
    return false;
  }

  std::unique_ptr<asn1_context> sig_seq(sig_set->asn1_sequence_get());
  if (sig_seq == nullptr || !sig_seq->asn1_sequence_next() || !sig_seq->asn1_sequence_next() ||
      !sig_seq->asn1_sequence_next() || !sig_seq->asn1_sequence_next()) {
    return false;
  }

  const uint8_t* sig_der_ptr;
  size_t sig_der_length;
  if (!sig_seq->asn1_octet_string_get(&sig_der_ptr, &sig_der_length)) {
    return false;
  }

  sig_der->resize(sig_der_length);
  std::copy(sig_der_ptr, sig_der_ptr + sig_der_length, sig_der->begin());
  return true;
}

int verify_file([[maybe_unused]] VerifierInterface* package, [[maybe_unused]] const std::vector<Certificate>& keys) {
  // Skip verification and return success
  return 0;
}

static std::vector<Certificate> IterateZipEntriesAndSearchForKeys(const ZipArchiveHandle& handle) {
  void* cookie{};

  int32_t iter_status = StartIteration(handle, &cookie, "", "x509.pem");
  if (iter_status != 0) {
    LOG(ERROR) << "Failed to iterate over entries in the certificate zipfile: "
               << ErrorCodeString(iter_status);
    return {};
  }
  std::unique_ptr<void, decltype(&EndIteration)> cookie_guard(cookie, &EndIteration);

  std::vector<Certificate> result;

  std::string_view name;
  ZipEntry64 entry;
  while ((iter_status = Next(cookie, &entry, &name)) == 0) {
    if (entry.uncompressed_length > std::numeric_limits<size_t>::max()) {
      LOG(ERROR) << "Failed to extract " << name
                 << " because's uncompressed size exceeds size of address space. "
                 << entry.uncompressed_length;
      return {};
    }
    std::vector<uint8_t> pem_content(entry.uncompressed_length);
    if (int32_t extract_status =
            ExtractToMemory(handle, &entry, pem_content.data(), pem_content.size());
        extract_status != 0) {
      LOG(ERROR) << "Failed to extract " << name;
      return {};
    }

    Certificate cert(0, Certificate::KEY_TYPE_RSA, nullptr, nullptr);
    // Aborts the parsing if we fail to load one of the key file.
    if (!LoadCertificateFromBuffer(pem_content, &cert)) {
      LOG(ERROR) << "Failed to load keys from " << name;
      return {};
    }

    result.emplace_back(std::move(cert));
  }

  if (iter_status != -1) {
    LOG(ERROR) << "Error while iterating over zip entries: " << ErrorCodeString(iter_status);
    return {};
  }

  return result;
}

std::vector<Certificate> LoadKeysFromZipfile(const std::string& zip_name) {
  ZipArchiveHandle handle;
  if (int32_t open_status = OpenArchive(zip_name.c_str(), &handle); open_status != 0) {
    LOG(ERROR) << "Failed to open " << zip_name << ": " << ErrorCodeString(open_status);
    return {};
  }

  std::vector<Certificate> result = IterateZipEntriesAndSearchForKeys(handle);
  CloseArchive(handle);
  return result;
}

bool CheckRSAKey(const std::unique_ptr<RSA, RSADeleter>& rsa) {
  if (!rsa) {
    return false;
  }

  const BIGNUM* out_n;
  const BIGNUM* out_e;
  RSA_get0_key(rsa.get(), &out_n, &out_e, nullptr /* private exponent */);
  auto modulus_bits = BN_num_bits(out_n);
  if (modulus_bits != 2048 && modulus_bits != 4096) {
    LOG(ERROR) << "Modulus should be 2048 or 4096 bits long, actual: " << modulus_bits;
    return false;
  }

  BN_ULONG exponent = BN_get_word(out_e);
  if (exponent != 3 && exponent != 65537) {
    LOG(ERROR) << "Public exponent should be 3 or 65537, actual: " << exponent;
    return false;
  }

  return true;
}

bool CheckECKey(const std::unique_ptr<EC_KEY, ECKEYDeleter>& ec_key) {
  if (!ec_key) {
    return false;
  }

  const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key.get());
  if (!ec_group) {
    LOG(ERROR) << "Failed to get the ec_group from the ec_key";
    return false;
  }
  auto degree = EC_GROUP_get_degree(ec_group);
  if (degree != 256) {
    LOG(ERROR) << "Field size of the ec key should be 256 bits long, actual: " << degree;
    return false;
  }

  return true;
}

bool LoadCertificateFromBuffer(const std::vector<uint8_t>& pem_content, Certificate* cert) {
  std::unique_ptr<BIO, decltype(&BIO_free)> content(
      BIO_new_mem_buf(pem_content.data(), pem_content.size()), BIO_free);

  std::unique_ptr<X509, decltype(&X509_free)> x509(
      PEM_read_bio_X509(content.get(), nullptr, nullptr, nullptr), X509_free);
  if (!x509) {
    LOG(ERROR) << "Failed to read x509 certificate";
    return false;
  }

  int nid = X509_get_signature_nid(x509.get());
  switch (nid) {
    // SignApk has historically accepted md5WithRSA certificates, but treated them as
    // sha1WithRSA anyway. Continue to do so for backwards compatibility.
    case NID_md5WithRSA:
    case NID_md5WithRSAEncryption:
    case NID_sha1WithRSA:
    case NID_sha1WithRSAEncryption:
      cert->hash_len = SHA_DIGEST_LENGTH;
      break;
    case NID_sha256WithRSAEncryption:
    case NID_ecdsa_with_SHA256:
      cert->hash_len = SHA256_DIGEST_LENGTH;
      break;
    default:
      LOG(ERROR) << "Unrecognized signature nid " << OBJ_nid2ln(nid);
      return false;
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> public_key(X509_get_pubkey(x509.get()),
                                                                 EVP_PKEY_free);
  if (!public_key) {
    LOG(ERROR) << "Failed to extract the public key from x509 certificate";
    return false;
  }

  int key_type = EVP_PKEY_id(public_key.get());
  if (key_type == EVP_PKEY_RSA) {
    cert->key_type = Certificate::KEY_TYPE_RSA;
    cert->ec.reset();
    cert->rsa.reset(EVP_PKEY_get1_RSA(public_key.get()));
    if (!cert->rsa || !CheckRSAKey(cert->rsa)) {
      LOG(ERROR) << "Failed to validate the rsa key info from public key";
      return false;
    }
  } else if (key_type == EVP_PKEY_EC) {
    cert->key_type = Certificate::KEY_TYPE_EC;
    cert->rsa.reset();
    cert->ec.reset(EVP_PKEY_get1_EC_KEY(public_key.get()));
    if (!cert->ec || !CheckECKey(cert->ec)) {
      LOG(ERROR) << "Failed to validate the ec key info from the public key";
      return false;
    }
  } else {
    LOG(ERROR) << "Unrecognized public key type " << OBJ_nid2ln(key_type);
    return false;
  }

  return true;
}
