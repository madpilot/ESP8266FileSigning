// References:
// http://vec3.ca/simple-digital-signatures/
// http://stackoverflow.com/questions/16224184/openssl-rsa-signature-verification-hash-and-padding
#include "FS.h"
#include "sha1.h"

void setup() {
  Serial.begin(115200);

  int i;
  unsigned char *data;
  int data_size;
  unsigned char hash[SHA1_SIZE];
  unsigned char hash_computed[SHA1_SIZE];
  
  SPIFFS.begin();

  Serial.println("Loading data.txt");
  File f1 = SPIFFS.open("/data.txt", "r");
  data_size = f1.size();
  data = (unsigned char *)malloc(sizeof(unsigned char) * data_size);
  f1.read(data, data_size);
  f1.close();

  Serial.println("Loading hash");
  File f2 = SPIFFS.open("/hash", "r");
  f2.read(hash, SHA1_SIZE);
  f2.close();
  SPIFFS.end();

  Serial.println("Computing the hash");
  SHA1_CTX md;
  SHA1_Init(&md);
  SHA1_Update(&md, (const uint8_t*)data, data_size);
  SHA1_Final(hash_computed, &md);

  if(memcmp(hash, hash_computed, SHA1_SIZE) == 0) {
    Serial.println("Hash matches");
  } else {
    Serial.println("Hash does not match");
  }
}

void loop() {
  // put your main code here, to run repeatedly:
}
