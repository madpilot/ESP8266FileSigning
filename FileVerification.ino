// References:
// http://vec3.ca/simple-digital-signatures/
// http://stackoverflow.com/questions/16224184/openssl-rsa-signature-verification-hash-and-padding
// http://stackoverflow.com/questions/10782826/digital-signature-for-a-file-using-openssl

#include "ca.h"
#include "FS.h"
#include "rsa.h"
#include "asn1.h"
#include "sha1.h"
#include "sha256.h"

void setup() {
  Serial.begin(115200);

  /* Data variables */
  unsigned char *data;
  int data_size;

  /* Cert variables */
  unsigned char *cert;
  int cert_size;

  /* Hash variables */
  unsigned char *sig;
  int sig_size;
  unsigned char *hash;
  unsigned char hash_computed[SHA256_SIZE];

  /* RSA variables */
  #define MAX_KEY_LEN 512

  int x509_res;

  SPIFFS.begin();

  Serial.println("Setting up CA");

  CA_CERT_CTX *ca_ctx;
  ca_ctx = (CA_CERT_CTX *)malloc(sizeof(CA_CERT_CTX));
  x509_res = x509_new((const uint8_t *)ca_crt_der, &ca_crt_der_len, &(ca_ctx->cert[0]));
  if(x509_res != X509_OK) {
    Serial.print("Could not load CA certificate: ");
    Serial.println(x509_res);
    return;
  } else {
    Serial.print("Loaded CA certificate. Common Name: ");
    Serial.println(ca_ctx->cert[0]->cert_dn[X509_COMMON_NAME]);
  }
  
  Serial.println("Loading developer.crt.der");
  File f2 = SPIFFS.open("/developer.crt.der", "r");
  cert_size = f2.size();
  cert = (unsigned char *)malloc(sizeof(unsigned char) * cert_size);
  f2.read(cert, cert_size);
  f2.close();

  X509_CTX *x509_ctx = NULL;
  x509_res = x509_new(cert, &cert_size, &x509_ctx);
  if(x509_res != X509_OK) {
    Serial.print("Could not load certificate: ");
    Serial.println(x509_res);
    return;
  } else {
    Serial.print("Loaded developer certificate. Common Name: ");
    Serial.println(x509_ctx->cert_dn[X509_COMMON_NAME]);
  }

  Serial.println("Loading data.txt");
  File f1 = SPIFFS.open("/data.txt", "r");
  data_size = f1.size();
  data = (unsigned char *)malloc(sizeof(unsigned char) * data_size);
  f1.read(data, data_size);
  f1.close();
  
  int constraint;
  int verify_res = x509_verify(ca_ctx, x509_ctx, &constraint);

  if(verify_res == 0) {
    Serial.println("Developer certificate verified");
  } else {
    Serial.print("Developer certificate verification failed: ");
    Serial.println(verify_res);
    return;
  }
  
  Serial.println("Loading sig256");
  File f3 = SPIFFS.open("/sig256", "r");
  sig_size = f3.size();
  sig = (unsigned char *)malloc(sizeof(unsigned char) * sig_size);
  f3.read(sig, sig_size);
  f3.close();
  SPIFFS.end();

  Serial.println("Decrypting the SHA256 hash");
  unsigned char sig_bytes[MAX_KEY_LEN];
  int len = RSA_decrypt(x509_ctx->rsa_ctx, (const uint8_t*)sig, sig_bytes, MAX_KEY_LEN, 0);

  if(len == -1) {
    Serial.println("Invalid signature");
    return;
  }
  if(len < SHA256_SIZE) {
    Serial.println("Signature too short");
    return;
  }
  hash = sig_bytes + len - SHA256_SIZE;

  Serial.println("Computing the SHA256 hash");
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, (const uint8_t*)data, data_size);
  SHA256_Final(hash_computed, &sha256);

  if(memcmp(hash, hash_computed, SHA256_SIZE) == 0) {
    Serial.println("SHA256 Hash matches");
  } else {
    Serial.println("SHA256 Hash does not match");
  }
}

void loop() {
  // put your main code here, to run repeatedly:
}
