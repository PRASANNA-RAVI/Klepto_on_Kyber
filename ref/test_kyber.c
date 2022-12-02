#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "randombytes.h"
#include "indcpa.h"
#include "klepto_attack.h"
// #include "rng.h"
#include "crypto_kem.h"

#define NTESTS 1000000

// static int test_keys()
// {
//   uint8_t pk[crypto_kem_PUBLICKEYBYTES];
//   uint8_t sk[crypto_kem_SECRETKEYBYTES];
//   uint8_t ct[crypto_kem_CIPHERTEXTBYTES];
//   uint8_t key_a[crypto_kem_BYTES];
//   uint8_t key_b[crypto_kem_BYTES];
//
//   //Alice generates a public key
//   cm_crypto_kem_keypair(pk, sk);
//
//   //Bob derives a secret key and creates a response
//   cm_crypto_kem_enc(ct, key_b, pk);
//
//   //Alice uses Bobs response to get her shared key
//   cm_crypto_kem_dec(key_a, ct, sk);
//
//   printf("Ciphertext to be Printed...\n");
//   for(int i = 0; i < crypto_kem_CIPHERTEXTBYTES; i++)
//   {
//     printf("%02x, ", ct[i]);
//   }
//   printf("\n");
//
//   if(memcmp(key_a, key_b, crypto_kem_BYTES))
//   {
//     printf("ERROR keys\n");
//     return 1;
//   }
//   else
//   {
//     printf("Success keys\n");
//   }
//
//   return 0;
// }
//
//
// static int test_keys()
// {
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key_a[CRYPTO_BYTES];
//   uint8_t key_b[CRYPTO_BYTES];
//
//   //Alice generates a public key
//   crypto_kem_keypair(pk, sk);
//
//   //Bob derives a secret key and creates a response
//   crypto_kem_enc(ct, key_b, pk);
//
//   //Alice uses Bobs response to get her shared key
//   crypto_kem_dec(key_a, ct, sk);
//
//   if(memcmp(key_a, key_b, CRYPTO_BYTES))
//   {
//     // printf("ERROR keys\n");
//     return 1;
//   }
//
//   return 0;
// }

static int test_klepto_attack()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  // Here, I can basically create the public secret key pair...and also the shared secret... Then, use the same as noise seed... That will be simpler...

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  #if (KLEPTO_KEYGEN == 1)
  klepto_keygen_attacker_function(1);
  #endif

  for(int kk = 0; kk < 1; kk++)
  {
    //Bob derives a secret key and creates a response
    crypto_kem_enc(ct, key_b, pk);

    //Alice uses Bobs response to get her shared key
    crypto_kem_dec(key_a, ct, sk);

    if(memcmp(key_a, key_b, CRYPTO_BYTES))
    {
      printf("ERROR keys\n");
      return -1;
    }
    else
    {
      printf("CORRECT keys...\n");
      // break;
    }

  }


  return 0;
}

int main(void)
{
  unsigned int i;
  int r;

  #if (KLEPTO_KEYGEN == 1 || KLEPTO_ENCAPS == 1)
  klepto_keygen_attacker_function(0);
  #endif

  i = 0;

  for(i = 0; i < NTESTS; i++)
  {

    if(i % 1 == 0)
    {
      printf("Iterations: %d\n", i);
    }

    r = test_klepto_attack();

    if(r)
      return 1;
  }

  return 0;
}
