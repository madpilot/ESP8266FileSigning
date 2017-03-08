// References:
// http://vec3.ca/simple-digital-signatures/
// http://stackoverflow.com/questions/16224184/openssl-rsa-signature-verification-hash-and-padding
#include "FS.h"
#include "rsa.h"
#include "sha1.h"
#include "sha256.h"

void setup() {
  Serial.begin(115200);

  /* Data variables */
  unsigned char *data;
  int data_size;

  /* Hash variables */
  unsigned char *sig;
  int sig_size;
  unsigned char *hash;
  unsigned char hash_computed[SHA256_SIZE];

  /* RSA variables */
  #define MAX_KEY_LEN 512
  
  unsigned char *modulus;
  int modulus_len;
  unsigned char *exponent = 0x10001;
  int exponent_len = ;
  
  SPIFFS.begin();

  Serial.println("Loading data.txt");
  File f1 = SPIFFS.open("/data.txt", "r");
  data_size = f1.size();
  data = (unsigned char *)malloc(sizeof(unsigned char) * data_size);
  f1.read(data, data_size);
  f1.close();

  Serial.println("Loading sig256");
  File f3 = SPIFFS.open("/sig256", "r");
  sig_size = f3.size();
  sig = (unsigned char *)malloc(sizeof(unsigned char) * sig_size);
  f3.read(sig, sig_size);
  f3.close();
  SPIFFS.end();

  Serial.println("Decrypting the SHA256 hash");
  RSA_CTX *rsa = NULL;
  RSA_pub_key_new(&rsa, modulus, modulus_len, exponent, exponent_len);
  if(!rsa) {
    Serial.println("Out of memory");
    return;
  }
  unsigned char sig_bytes[MAX_KEY_LEN];
  int len = RSA_decrypt(rsa, (const uint8_t*)sig, sig_bytes, 0, 1);
  RSA_free(rsa);

  if(len == -1 || len < SHA256_SIZE) {
    Serial.println("Invalida signature");
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
