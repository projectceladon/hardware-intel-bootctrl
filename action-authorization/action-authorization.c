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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/time.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "rma_certificate.h"


static void usage(char *cmd, int status)
{
	FILE *out = status == EXIT_SUCCESS ? stdout : stderr;

	fprintf(out, "Usage: %s [OPTIONS]\n"
		"	\n"
		"	Produce a answer message to a fastboot get-action-nonce.\n"
		"	This message can be sent using the fastboot flash action-authorization\n"
		"	<file> command.\n"
		"	\n"
		"	--oak-cert, -O <file>          OAK certificate (PEM)\n"
		"	--oak-private-key, -K <file>   private key file (PEM)\n"
		"	--message, -M <string>         message received from get-action-nonce\n"
		"	fastboot command\n"
		"	--output-file, -F <file>       output file for the PKCS7 message\n"
		"	--help, -h                     display this help and exit\n", cmd);

	exit(status);
}

static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"oak-cert", required_argument, 0, 'O'},
	{"oak-private-key", required_argument, 0, 'K'},
	{"message", required_argument, 0, 'M'},
	{"output-file", required_argument, 0, 'F' },
	{0, 0, 0, 0}
};

static int save_file(const char *file, char *buf, int len)
{
	FILE *fp;

	fp = fopen(file, "wb");
	if (fp == NULL)
		return -1;

	fwrite(buf, 1, len, fp);
	fclose(fp);
	return 0;
}

static X509 *load_public_key_file(const char *file)
{
	X509 *cert;
	BIO *cert_bio;

	cert_bio = BIO_new_file(file, "rb");
	if (!cert_bio)
		return NULL;

	cert = PEM_read_bio_X509_AUX(cert_bio, NULL, NULL, NULL);
	BIO_free(cert_bio);

	return cert;
}

EVP_PKEY *load_private_key_file(const char *file)
{
	EVP_PKEY *private_key;
	BIO *key_bio;

	key_bio = BIO_new_file(file, "rb");
	if (!key_bio)
		return NULL;

	private_key = d2i_PrivateKey_bio(key_bio, NULL);
	BIO_free(key_bio);
	if (private_key == NULL)
		return NULL;

	return private_key;
}

static int generate_rma_cerificate(const char *key_file, const char *cert_file, char *nonce, const char *out_file)
{
	EVP_MD_CTX mdctx;
	RMA_CERTIFICATE *rma_cert = NULL;
	EVP_PKEY *private_key = NULL;
	X509 *x509 = NULL;
	unsigned char *sign_value = NULL;
	char *der = NULL;
	char *p;
	int sign_len;
	int len;
	int ret = -1;

	do {
		private_key = load_private_key_file(key_file);
		if (private_key == NULL) {
			fprintf(stdout, "Failed to load the private key '%s'\n", key_file);
			break;
		}

		x509 = load_public_key_file(cert_file);
		if (x509 == NULL) {
			fprintf(stdout, "Failed to load the public key '%s'\n", cert_file);
			break;
		}

		rma_cert = RMA_CERTIFICATE_new();
		if (rma_cert == NULL)
			break;

		rma_cert->x509 = x509;
		x509 = NULL;
		ASN1_OCTET_STRING_set(rma_cert->nonce, (const unsigned char *)nonce, strlen(nonce));

		EVP_MD_CTX_init(&mdctx);
		if (EVP_SignInit_ex(&mdctx, EVP_sha256(), NULL) <= 0)
			break;

		if (EVP_SignUpdate(&mdctx, rma_cert->nonce->data, rma_cert->nonce->length) <= 0)
			break;

		sign_len = EVP_PKEY_size(private_key);
		sign_value = malloc(sign_len);
		if (sign_value == NULL)
			break;
		if (EVP_SignFinal(&mdctx, sign_value, &sign_len, private_key) <= 0) {
			fprintf(stdout, "error for EVP_SignFinal\n");
			break;
		}
		ASN1_STRING_set0(rma_cert->digest, sign_value, sign_len);
		sign_value = NULL;
		EVP_MD_CTX_cleanup(&mdctx);

		len = i2d_RMA_CERTIFICATE(rma_cert, NULL);
		der = (char *)malloc(len);
		if (der == NULL)
			break;

		p = der;
		len = i2d_RMA_CERTIFICATE(rma_cert, (unsigned char **)&p);
		save_file(out_file, der, len);
		ret = EXIT_SUCCESS;
	}	while (0);

	if (der != NULL)
		free(der);
	if (sign_value != NULL)
		free(sign_value);
	if (private_key)
		EVP_PKEY_free(private_key);
	if (x509 != NULL)
		X509_free(x509);
	if (rma_cert != NULL)
		RMA_CERTIFICATE_free(rma_cert);

	return ret;
}

int main(int argc, char **argv)
{
	char *key_file = NULL;
	char *cert_file = NULL;
	char *out_file = NULL;
	char *message = NULL;
	char c, *cmd;
	int option_index = 0;
	int ret = EXIT_FAILURE;

	cmd = basename(argv[0]);
	while (1) {
		c = getopt_long(argc, argv, "hO:K:A:M:F:P:V",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 0:
			break;

		case 'h':
			usage(cmd, EXIT_SUCCESS);
			break;

		case 'O':
			cert_file = optarg;
			break;

		case 'K':
			key_file = optarg;
			break;

		case 'M':
			message = optarg;
			break;

		case 'F':
			out_file = optarg;
			break;

		default:
			usage(cmd, EXIT_FAILURE);
			break;
		}
	}

	if (!key_file || !cert_file || !out_file || !message)
		usage(cmd, EXIT_FAILURE);

	ret = generate_rma_cerificate(key_file, cert_file, message, out_file);
	if (ret == EXIT_SUCCESS)
		fprintf(stdout, "'%s' successfully generated.\n", out_file);
	else
		fprintf(stdout, "'%s' generate failed.\n", out_file);

	return ret;
}

