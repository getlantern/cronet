// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CRONET_WEBTRANSPORT_CERT_VERIFY_PROC_PINNED_H_
#define COMPONENTS_CRONET_WEBTRANSPORT_CERT_VERIFY_PROC_PINNED_H_

#include "crypto/sha2.h"
#include "net/base/net_export.h"
#include "net/cert/cert_verify_proc.h"

using ::net::SHA256HashValue;

class CertVerifyProcPinned : public net::CertVerifyProc {
 public:
  explicit CertVerifyProcPinned(SHA256HashValue fingerprint, bool insecureSkipVerify=false);
  explicit CertVerifyProcPinned(bool insecureSkipVerify=false);

  CertVerifyProcPinned(const CertVerifyProcPinned&) = delete;
  CertVerifyProcPinned& operator=(const CertVerifyProcPinned&) = delete;

  int Verify(net::X509Certificate* cert,
             const std::string& hostname,
             const std::string& ocsp_response,
             const std::string& sct_list,
             int flags,
             net::CRLSet* crl_set,
             const net::CertificateList& additional_trust_anchors,
             net::CertVerifyResult* verify_result,
             const net::NetLogWithSource& net_log) override;

  bool SupportsAdditionalTrustAnchors() const override;

  void SetPinnedCert(SHA256HashValue fingerprint);

 protected:
  ~CertVerifyProcPinned() override;
  bool _isPinned(net::X509Certificate* cert);

 private:
  int VerifyInternal(net::X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     const std::string& sct_list,
                     int flags,
                     net::CRLSet* crl_set,
                     const net::CertificateList& additional_trust_anchors,
                     net::CertVerifyResult* verify_result,
                     const net::NetLogWithSource& net_log) override;

  SHA256HashValue _pinned;
  bool _insecureSkipVerify;
};

#endif  // _COMPONENTS_CRONET_WEBTX_CERT_VERIFY_PROC_PINNED_H_
