#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

// 64-bit left rotate assembly I wrote
#define rol(n, shift) asm volatile ("rol %%cl, %1" : "=r" (n) : "r" (n), "c" (shift))
#define ror(n, shift) asm volatile ("ror %%cl, %1" : "=r" (n) : "r" (n), "c" (shift))

// 64-bit int pow
#define pow64(n1, n2) ((uint64_t)pow(n1, n2))

// attempt at implementing threefish 256-bit

// the size of a threefish word is 64 bits
#define TF_WORD uint64_t

// constant c240 from the paper for key generation
#define c240 0x1BD11BDAA9FC1A22

// for 256 bit threefish, the key must be:
// 4 words + the xor of them

// constants for 256 rounds

int dw[] = {
  14, 16,
  52, 57,
  23, 40,
  5, 37,
  25, 33,
  46, 12,
  58, 22,
  32, 32
};

void run_1_round(TF_WORD * bsk, TF_WORD * tweak, TF_WORD * data, int rnd) {
  if(rnd % 4 == 0) { // every 4th round (including round 0)
    for(int i = 0;i < 4;i++) { // iterate each word
      int s = rnd / 4; // s = d/4
      int key_index = (s + i) % (4 + 1); // (s + i) % (w + 1)
      TF_WORD key_base = bsk[key_index];
      switch(i) {
        case 0:
        break;
        case 1:
          key_base += tweak[s % 3];
        break;
        case 2:
          key_base += tweak[(s + 1) % 3];
        break;
        case 3:
          key_base += s;
        break;
      }
      
      // now the key is derived, do the encryption
      
      data[i] = (data[i] + key_base) % ULLONG_MAX;
    }
  }
  
  // now do the mixing
  for(int i = 0;i < 4;i+=2) {
    TF_WORD y0 = (data[i] + data[i + 1]) % ULLONG_MAX;
    TF_WORD tmp_dat = data[i + 1] + 0; // temporary var for the rol
    TF_WORD data_word = dw[(i / 2) + (rnd % 8) * 2];
    rol(tmp_dat, data_word);
    TF_WORD y1 = tmp_dat ^ y0;
    data[i] = y0;
    data[i + 1] = y1;
  }
}

void enc_tf256(TF_WORD * bsk, TF_WORD * tweak, TF_WORD * data) {
  // in this:
  // plaintext is data[0], data[1], data[2], data[3]
  
  for(int r = 0;r < 72;r++) {
    run_1_round(bsk, tweak, data, r);
    
    printf("Round %d\n", r);
    printf("%llx %llx %llx %llx\n", data[0], data[1], data[2], data[3]);
  }
  
  int rnd = 72;
  
  for(int i = 0;i < 4;i++) { // iterate each word
    int s = rnd / 4; // s = d/4
    int key_index = (s + i) % (4 + 1); // (s + i) % (w + 1)
    TF_WORD key_base = bsk[key_index];
    switch(i) {
      case 0:
      break;
      case 1:
        key_base += tweak[s % 3];
      break;
      case 2:
        key_base += tweak[(s + 1) % 3];
      break;
      case 3:
        key_base += s;
      break;
    }
    
    // now the key is derived, do the encryption
    
    data[i] = (data[i] + key_base) % ULLONG_MAX;
  }
    
  printf("Round 72\n");
  printf("%llx %llx %llx %llx\n", data[0], data[1], data[2], data[3]);
    
}

void dec_1_round(TF_WORD * bsk, TF_WORD * tweak, TF_WORD * data, int rnd) {
  // now do the mixing
  for(int i = 0;i < 4;i+=2) {
    TF_WORD data_word = dw[(i / 2) + (rnd % 8) * 2];
    
    TF_WORD y0 = data[i];
    TF_WORD y1 = data[i + 1];
    
    TF_WORD yr = y1 ^ y0;
    TF_WORD tmp_data = yr + 0;
    
    ror(tmp_data, data_word);
    
    TF_WORD x1 = tmp_data;
    TF_WORD x0 = y0 - x1;
    data[i] = x0;
    data[i + 1] = x1;
  }
  
  if(rnd % 4 == 0) { // every 4th round (including round 0)
    for(int i = 0;i < 4;i++) { // iterate each word
      int s = rnd / 4; // s = d/4
      int key_index = (s + i) % (4 + 1); // (s + i) % (w + 1)
      TF_WORD key_base = bsk[key_index];
      switch(i) {
        case 0:
        break;
        case 1:
          key_base += tweak[s % 3];
        break;
        case 2:
          key_base += tweak[(s + 1) % 3];
        break;
        case 3:
          key_base += s;
        break;
      }
      
      // now the key is derived, do the encryption
      
      data[i] = (data[i] - key_base) % ULLONG_MAX;
    }
  }
}

void dec_tf256(TF_WORD * bsk, TF_WORD * tweak, TF_WORD * data) {
  // first step is the final key
  
  int rnd = 72;
  
  for(int i = 0;i < 4;i++) { // iterate each word
      int s = rnd / 4; // s = d/4
      int key_index = (s + i) % (4 + 1); // (s + i) % (w + 1)
      TF_WORD key_base = bsk[key_index];
      switch(i) {
        case 0:
        break;
        case 1:
          key_base += tweak[s % 3];
        break;
        case 2:
          key_base += tweak[(s + 1) % 3];
        break;
        case 3:
          key_base += s;
        break;
      }
      
      // now the key is derived, do the encryption
      
      data[i] = (data[i] - key_base) % ULLONG_MAX;
  }
  
  //printf("Reverse Round 72 = Round 71\n");
  //printf("%llx %llx %llx %llx\n", data[0], data[1], data[2], data[3]);
  
  for(int r = 71; r >= 0; r--) {
    // then reverse the other steps
    dec_1_round(bsk, tweak, data, r);
    printf("Reverse round %d\n", r);
    printf("%llx %llx %llx %llx\n", data[0], data[1], data[2], data[3]);
  }
  
  printf("Reverse Data\n");
  printf("%c %c %c %c\n", data[0], data[1], data[2], data[3]);
}

// the rol seems to be working
void test_rol() {
  uint64_t t = 1;
  uint64_t p = pow64(2, 0);
  
  for(int i = 1;i < 64;i++) {
    p = pow64(2, i);
    rol(t, (uint64_t)1); // changes t in-place
    
    if(p != t) {
      printf("ERR\n");
      printf("%u != %u\n", p, t);
      exit(0);
    }
  }
  
  printf("success\n");
}

int main() {
  
  // key
  TF_WORD key[] = {
    0xAAAAAAB, 0xFFFFAEF, 0xFAEEFCC11F, 0xFAA451F, 0x00
  };
  
  // 5th key value is the xor of the other words
  key[4] = c240 ^
           key[0] ^
           key[1] ^
           key[2] ^
           key[3];
  
  // tweak is 2 words
  TF_WORD twk[] = {
    0xFF, 0xFF, 0x00
  };
  
  // 3rd word is the xor
  twk[2] = twk[0] ^ twk[1];
  
  // data is only 4 words, key is 5 for rotation
  TF_WORD data[] = {
    'F', 'U', 'C', 'K'
  };
  
  // pass them all into the encryption function
  enc_tf256(key, twk, data);
  dec_tf256(key, twk, data);
  //test_rol();
}