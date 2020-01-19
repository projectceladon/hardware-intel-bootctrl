/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __RMA_CERTIFICATE_H__
#define __RMA_CERTIFICATE_H__

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>

typedef struct RMA_CERTIFICATE_st {
	X509 *x509;
	ASN1_OCTET_STRING *nonce;
	ASN1_OCTET_STRING *digest;
} RMA_CERTIFICATE;
DECLARE_ASN1_FUNCTIONS(RMA_CERTIFICATE)

ASN1_SEQUENCE(RMA_CERTIFICATE) = {
	ASN1_SIMPLE(RMA_CERTIFICATE, x509, X509),
	ASN1_SIMPLE(RMA_CERTIFICATE, nonce, ASN1_OCTET_STRING),
	ASN1_SIMPLE(RMA_CERTIFICATE, digest, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(RMA_CERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(RMA_CERTIFICATE)

#endif // __RMA_CERTIFICATE_H__

