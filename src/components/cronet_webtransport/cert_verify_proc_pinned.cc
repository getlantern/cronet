// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/cronet_webtransport/cert_verify_proc_pinned.h"

#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <vector>



#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/known_roots.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"



std::string fingerprintHex(SHA256HashValue fingerprint)
{
     std::stringstream ss;
     ss << std::hex;

     for( int i(0) ; i < 32; ++i )
         ss << std::setw(2) << std::setfill('0') << (int)fingerprint.data[i];

     return ss.str();
}

CertVerifyProcPinned::CertVerifyProcPinned(SHA256HashValue fingerprint, bool insecureSkipVerify): _pinned(fingerprint), _insecureSkipVerify(insecureSkipVerify) {
  LOG(ERROR) << "CertVerifyProcPinned constructed with fingerprint " << fingerprintHex(fingerprint) << "\n"; 
}

CertVerifyProcPinned::CertVerifyProcPinned(bool insecureSkipVerify): _insecureSkipVerify(insecureSkipVerify) {
}


CertVerifyProcPinned::~CertVerifyProcPinned() {
}

bool CertVerifyProcPinned::SupportsAdditionalTrustAnchors() const {
  return false;
}

void CertVerifyProcPinned::SetPinnedCert(SHA256HashValue fingerprint) {
  LOG(ERROR) << "CertVerifyProcPinned::SetPinnedCert called.\n";
  _pinned = fingerprint;
}

int CertVerifyProcPinned::Verify(net::X509Certificate* cert,
           const std::string& hostname,
           const std::string& ocsp_response,
           const std::string& sct_list,
           int flags,
           net::CRLSet* crl_set,
           const net::CertificateList& additional_trust_anchors,
           net::CertVerifyResult* verify_result,
           const net::NetLogWithSource& net_log) {

  verify_result->Reset();
  verify_result->verified_cert = cert;

  DCHECK(crl_set);
  int rv =
      VerifyInternal(cert, hostname, ocsp_response, sct_list, flags, crl_set,
                     additional_trust_anchors, verify_result, net_log);

  // Skips a bunch of certificate sanity checks performed by default which 
  // are actually really important under normal circumstances...
  // ie the name the certificate presents matches the host we were trying to 
  // contact etc etc.

  return rv;
}

int CertVerifyProcPinned::VerifyInternal(
    net::X509Certificate* cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    const std::string& sct_list,
    int flags,
    net::CRLSet* crl_set,
    const net::CertificateList& additional_trust_anchors,
    net::CertVerifyResult* verify_result,
    const net::NetLogWithSource& net_log) {

  LOG(ERROR) << "CertVerifyProcPinned::VerifyInternal...\n"; 

  if (_insecureSkipVerify || _isPinned(cert)) {
    // verify_result->Reset();
    // verify_result->verified_cert = cert;
    // verify_result->is_issued_by_known_root = true;
    // if (!ocsp_response.empty()) {
    //   verify_result->ocsp_result.response_status =
    //       net::OCSPVerifyResult::PROVIDED;
    //   verify_result->ocsp_result.revocation_status =
    //       net::OCSPRevocationStatus::GOOD;
    // }
    verify_result->is_issued_by_known_root = true;
    LOG(ERROR) << "CertVerifyProcPinned::VerifyInternal returning net::OK\n"; 
    return net::OK;
  }

  LOG(ERROR) << "CertVerifyProcPinned::VerifyInternal returning net::ERR_CERT_INVALID\n"; 
  verify_result->cert_status |= net::CERT_STATUS_INVALID;
  return net::ERR_CERT_INVALID;
}

bool CertVerifyProcPinned::_isPinned(net::X509Certificate* cert) {
  base::StringPiece cert_spki;
  SHA256HashValue hash;
  if (net::asn1::ExtractSPKIFromDERCert(
        net::x509_util::CryptoBufferAsStringPiece(
            cert->cert_buffer()),
            &cert_spki)) {
      crypto::SHA256HashString(cert_spki, &hash, sizeof(SHA256HashValue));
      if (hash == _pinned) {
        LOG(ERROR) << "CertVerifyProcPinned::_isPinned certs matched!\n"; 
        return true;
      } else {
        LOG(ERROR) << "CertVerifyProcPinned::_isPinned certs did not match! " << fingerprintHex(hash) << " / " << fingerprintHex(_pinned) << "\n";
      }
  } else {
    LOG(ERROR) << "CertVerifyProcPinned::_isPinned failed to extract spki from der cert.\n";
  }

  // LOG(ERROR) << "CertVerifyProcPinned::_isPinned checking intermediates...\n";
  // for (const auto& intermediate : cert->intermediate_buffers()) {
  //   if (net::asn1::ExtractSPKIFromDERCert(
  //           net::x509_util::CryptoBufferAsStringPiece(intermediate.get()),
  //           &cert_spki)) {
  //     crypto::SHA256HashString(cert_spki, &hash, sizeof(SHA256HashValue));
  //     if (hash == _pinned) {
  //       LOG(ERROR) << "CertVerifyProcPinned::_isPinned certs matched! (intermediate)\n"; 
  //       return true;
  //     } else {
  //       LOG(ERROR) << "CertVerifyProcPinned::_isPinned certs did not match! " << fingerprintHex(hash) << " / " << fingerprintHex(_pinned) << "\n";
  //     }
  //   } else {
  //     LOG(ERROR) << "CertVerifyProcPinned::_isPinned failed to extract spki from der cert.\n";
  //   }
  // } 

  LOG(ERROR) << "CertVerifyProcPinned::_isPinned finished no match...\n";
  return false;
}