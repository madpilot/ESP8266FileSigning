// References:
// http://vec3.ca/simple-digital-signatures/
// http://stackoverflow.com/questions/16224184/openssl-rsa-signature-verification-hash-and-padding
#include "FS.h"
#include "sha1.h"
#include "sha256.h"

void setup() {
  Serial.begin(115200);

  unsigned char *data;
  int data_size;
  
  unsigned char hash1[SHA1_SIZE];
  unsigned char hash1_computed[SHA1_SIZE];

  unsigned char hash256[SHA256_SIZE];
  unsigned char hash256_computed[SHA256_SIZE];
  
  SPIFFS.begin();

  Serial.println("Loading data.txt");
  File f1 = SPIFFS.open("/data.txt", "r");
  data_size = f1.size();
  data = (unsigned char *)malloc(sizeof(unsigned char) * data_size);
  f1.read(data, data_size);
  f1.close();

  Serial.println("Loading hash1");
  File f2 = SPIFFS.open("/hash1", "r");
  f2.read(hash1, SHA1_SIZE);
  f2.close();

  Serial.println("Loading hash256");
  File f3 = SPIFFS.open("/hash256", "r");
  f3.read(hash256, SHA256_SIZE);
  f3.close();
  SPIFFS.end();

  Serial.println("Computing the SHA1 hash");
  SHA1_CTX sha1;
  SHA1_Init(&sha1);
  SHA1_Update(&sha1, (const uint8_t*)data, data_size);
  SHA1_Final(hash1_computed, &sha1);

  if(memcmp(hash1, hash1_computed, SHA1_SIZE) == 0) {
    Serial.println("SHA1 Hash matches");
  } else {
    Serial.println("SHA1 Hash does not match");
  }

  Serial.println("Computing the SHA256 hash");
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, (const uint8_t*)data, data_size);
  SHA256_Final(hash256_computed, &sha256);

  if(memcmp(hash256, hash256_computed, SHA256_SIZE) == 0) {
    Serial.println("SHA256 Hash matches");
  } else {
    Serial.println("SHA256 Hash does not match");
  }

}

void loop() {
  // put your main code here, to run repeatedly:
}
