/*
****************************************************************************
AES CBC MODE ENCRYPTION AND DECRYPTION SCHEME MANUAL IMPLMENTATION
****************************************************************************
NOTE : For learning purpose only and will not be implmented in any program.
----------------------------------------------------------------------------
High-level description of the algorithm :
-------------------------------------------

  General concept to be followed in preprocessing the key, plainText, cipherText strings :

  - Write a preprocessing function that takes in key and plainText/Cipertext char strings with special arguments int K, P/C where
    - K == 1 => K is in hex , K == 0 => K is in char, similarly with P/C.
    -Also takes an extra argument int task, which if == 1 => encryption as to be performed, and == 0 => decryption has to be performed.

    - Concept to be followed in converting strings to the corresponding hex bytes string
    -- If the given string is in hex, 
               -- allocate numBytes = numChars in string/2 
               -- make a function which returns (byte)(16 * c1 + c2) 
               -- using above function recursively on the given string output the hex byte string 

   -- If given string is in char,
               -- allocate numBytes = numChars in the string
               -- make a function that returns (byte)char
               -- use this function recursively to asign values to the output string

   - Specifically for the plain text (Encryption) apply padding,
         - Concept to be followed in the padding [ using reallocation ]
               -- if the numBytes in the plain text hex string is a multiple of 4*Nb then add one more block
                  to the string of 4*Nb bytes with each entry having value (byte)4*Nb
               -- else add the elements to hex string until the string becomes a multiple of 4*Nb bytes long and
                  assign each extra entry value = (byte)(Number of extra entries added)

    - Now second last task is to call the encryption and decryption function
            - loop on the num blocks and use cbc mode which is described below

   - Specifically for cipherText->plaintext (decryption) removing padding
         - take the last byte value convert it to int and remove that number of block from end using reallocation.

   AES CBC MODE ALGORITHM :

   - If the first block has index 1, the mathematical formula for CBC encryption is
      C_i = E_K(P_i XOR C_{i-1}), C_0 = IV
   - while the mathematical formula for CBC decryption is
      P_i = D_K(C_i) XOR C_{i-1}, C_0 = IV.

      WHERE E AND D ARE THE STANDARD AES ENCRYPTIN AND DECRYPTION SCHEMES FROM THE AES API.

      NOTE :::: The first 16 bytes of cipher is IV and ciphertext is always greater in length than plaintext.
*/

#include <cstdio>
#include <cstdlib>

using namespace std;

typedef unsigned char byte;

struct word
{
   byte alpha[4];
};

/**********************************************************************************************
S-BOX FORWARD
**********************************************************************************************/
byte s[256] = 
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/**********************************************************************************************
S-BOX INVERSE
**********************************************************************************************/
byte inv_s[256] = 
{
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
   0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
   0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
   0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
   0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
   0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
   0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
   0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
   0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
   0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
   0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/**********************************************************************************************
RCON BOX
**********************************************************************************************/
byte Rcon[256] = {
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};


/**********************************************************************************************
S-BOX SUBSTITUTION OF WORD : CHECK == 0 => FORWARD SUB. , CHECK == 1 => INV. SUB.
**********************************************************************************************/
word subWord(word input, int check)
{
   word output;

   if(check == 0)
   {
      for(int i = 0; i < 4; ++i)
      {
         output.alpha[i] = s[(int)input.alpha[i]];
      }
   }
   else
   {
      for(int i = 0; i < 4; ++i)
      {
         output.alpha[i] = inv_s[(int)input.alpha[i]];
      }
   }
   return output;
}

/**********************************************************************************************
ROTATION OF WORD
**********************************************************************************************/
word rotWord(word input)
{
   word output;
   byte temp;

   temp = input.alpha[0];

   for(int i = 0; i < 4 - 1; ++i)
      output.alpha[i] = input.alpha[i + 1];

   output.alpha[3] = temp;           

   return output;
}

/**********************************************************************************************
XOR TWO WORDS
**********************************************************************************************/
word xor_word(word a, word b)
{
   word output;

   for(int i = 0; i < 4; ++i)
   {
      output.alpha[i] = a.alpha[i] ^ b.alpha[i];
   }
   return output;
}

/******************************************************************************
KEY SCHEDULE/EXPANSION
*******************************************************************************/
void keyExpansion(byte key[], word *w,int Nk,int Nb,int Nr)
{

   word temp;
   int i = 0;

   while (i < Nk)
   {
      for(int j = 0; j < 4; ++j)
      {
         w[i].alpha[j] = key[4 * i + j];
      }
         i = i+1;
    }

   i = Nk;

   while (i < Nb * (Nr + 1))
    {
      temp = w[i-1];
      if (i % Nk == 0)
      {
         word temp2;
         temp2.alpha[0] = Rcon[i / Nk];
         temp2.alpha[1] = 0x00;
         temp2.alpha[2] = 0x00;
         temp2.alpha[3] = 0x00;

         temp = xor_word(subWord(rotWord(temp), 0), temp2);
      }
      else if (Nk > 6 && i % Nk == 4)
      {
         temp = subWord(temp, 0);
      }
      
      w[i] = xor_word(w[i-Nk], temp);
      i++;
   }
}

/**********************************************************************************************
ADDING ROUNDKEY
**********************************************************************************************/
void addRoundKey(word state[], word *w,int start,int end)
{
   for(int i = start; i < end + 1; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         state[i - start].alpha[j] ^= w[i].alpha[j]; 
      }
      
   }
}

/**********************************************************************************************
S-BOX SUBSTITUTION (FORWARD) OF A STATE WHICH IS 4 X 4
**********************************************************************************************/
void subBytes(word state[])
{
   for(int i = 0; i < 4; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         state[i].alpha[j] = s[(int)state[i].alpha[j]];
      }
   }
}

/**********************************************************************************************
S-BOX SUBSTITUTION (INVERSE) OF A STATE WHICH IS 4 X 4
**********************************************************************************************/
void invSubBytes(word state[])
{
   for(int i = 0; i < 4; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         state[i].alpha[j] = inv_s[(int)state[i].alpha[j]];
      }
   }
}

/**********************************************************************************************
SHIFT-ROWS
**********************************************************************************************/
void shiftRows(word state[])
{
   byte temp = state[1].alpha[0];

   for(int i = 0; i < 4 - 1; ++i)
   {
      state[1].alpha[i] = state[1].alpha[i + 1];
   }
   state[1].alpha[3] = temp;

   byte temp1 = state[2].alpha[0], temp2 = state[2].alpha[1];
   state[2].alpha[0] = state[2].alpha[2];
   state[2].alpha[1] = state[2].alpha[3];
   state[2].alpha[2] = temp1;
   state[2].alpha[3] = temp2;

   temp = state[3].alpha[3];
   for(int i = 3; i > 0; --i)
   {
      state[3].alpha[i] = state[3].alpha[i - 1];
   }
   state[3].alpha[0] = temp;
}

/**********************************************************************************************
SHIFT-ROWS INVERSE
**********************************************************************************************/
void invShiftRows(word state[])
{
   byte temp = state[3].alpha[0];

   for(int i = 0; i < 4 - 1; ++i)
   {
      state[3].alpha[i] = state[3].alpha[i + 1];
   }
   state[3].alpha[3] = temp;

   byte temp1 = state[2].alpha[0], temp2 = state[2].alpha[1];
   state[2].alpha[0] = state[2].alpha[2];
   state[2].alpha[1] = state[2].alpha[3];
   state[2].alpha[2] = temp1;
   state[2].alpha[3] = temp2;

   temp = state[1].alpha[3];
   for(int i = 3; i > 0; --i)
   {
      state[1].alpha[i] = state[1].alpha[i - 1];
   }
   state[1].alpha[0] = temp;
}

/**********************************************************************************************
MULTIPLY BY 2 I.E. 0x02 * a 
**********************************************************************************************/
byte multiplyBy2(byte a)
{
   byte a1;
   if(a << 1 > 0xFF)
      a1 = (a << 1) ^ 0x1b;
   else 
      a1 = a << 1;

   return a1;
}

/**********************************************************************************************
MULTIPLY BY 3 I.E. 0x03 * a
**********************************************************************************************/
byte multiplyBy3(byte a)
{
   byte a1;
   if(a << 1 > 0xFF)
      a1 = (a << 1) ^ 0x1b;
   else 
      a1 = a << 1;

   return a1^a;
}

/**********************************************************************************************
MIXING - COLUMNS
**********************************************************************************************/
void mixColumns(word state[])
{
   word temp[4];
   byte a , b, c, d, a1, b1, c1, d1;

   for(int i = 0; i < 4; ++i)
   {
      a = state[0].alpha[i];
      b = state[1].alpha[i];
      c = state[2].alpha[i];
      d = state[3].alpha[i];

      a1 = multiplyBy2(a);
      b1 = multiplyBy3(b);
      c1 = c;
      d1 = d;

      temp[0].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      b1 = multiplyBy2(b);
      c1 = multiplyBy3(c);
      a1 = a;
      d1 = d;

      temp[1].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      c1 = multiplyBy2(c);
      d1 = multiplyBy3(d);
      a1 = a;
      b1 = b;

      temp[2].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      d1 = multiplyBy2(d);
      a1 = multiplyBy3(a);
      c1 = c;
      b1 = b;

      temp[3].alpha[i] = a1 ^ b1 ^ c1 ^ d1;
   }
   
   for(int i = 0; i < 4; ++i)
      for(int j = 0; j < 4; ++j)
         state[i].alpha[j] = temp[i].alpha[j];

}

/**********************************************************************************************
MULTIPLY BY 9/11/13/14
**********************************************************************************************/
byte multiplyBy(byte a, int z)
{
   if(z == 9)
      return (multiplyBy2(multiplyBy2(multiplyBy2(a)))) ^ a;
   if(z == 11)
      return multiplyBy2((multiplyBy2(multiplyBy2(a))) ^ a) ^ a;
   if(z == 13)
      return multiplyBy2(multiplyBy2((multiplyBy2(a)) ^ a)) ^ a;
   if(z == 14)
       return multiplyBy2((multiplyBy2((multiplyBy2(a)) ^ a)) ^ a);

   return 0x00;
}

/**********************************************************************************************
INVERSE-MIXING-COLUMNS
**********************************************************************************************/
void invMixColumns(word state[])
{
   word temp[4];
   byte a , b, c, d, a1, b1, c1, d1;

   for(int i = 0; i < 4; ++i)
   {
      a = state[0].alpha[i];
      b = state[1].alpha[i];
      c = state[2].alpha[i];
      d = state[3].alpha[i];

      a1 = multiplyBy(a, 14);
      b1 = multiplyBy(b, 11);
      c1 = multiplyBy(c, 13);
      d1 = multiplyBy(d, 9);

      temp[0].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      a1 = multiplyBy(a, 9);
      b1 = multiplyBy(b, 14);
      c1 = multiplyBy(c, 11);
      d1 = multiplyBy(d, 13);

      temp[1].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      a1 = multiplyBy(a, 13);
      b1 = multiplyBy(b, 9);
      c1 = multiplyBy(c, 14);
      d1 = multiplyBy(d, 11);

      temp[2].alpha[i] = a1 ^ b1 ^ c1 ^ d1;

      a1 = multiplyBy(a, 11);
      b1 = multiplyBy(b, 13);
      c1 = multiplyBy(c, 9);
      d1 = multiplyBy(d, 14);

      temp[3].alpha[i] = a1 ^ b1 ^ c1 ^ d1;
   }
   
   for(int i = 0; i < 4; ++i)
      for(int j = 0; j < 4; ++j)
         state[i].alpha[j] = temp[i].alpha[j];

}

/**********************************************************************************************
BLOCK-ENCRYPTION-AES
**********************************************************************************************/
void blockEncryptionAes(byte in[], byte *out, word *w,int Nb,int Nr,int Nk)
{

   word state[4];

   for(int i = 0; i < 4; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         state[j].alpha[i] = in[4 * i + j];        
      }
   }

   addRoundKey(state, w, 0, Nb - 1);
   
   for(int rnd = 1; rnd < Nr; ++rnd)
   {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, w, rnd*Nb, (rnd + 1) * Nb - 1);
   }

   subBytes(state);
   shiftRows(state);
   addRoundKey(state, w, Nr*Nb, (Nr + 1) * Nb - 1);

   for(int i = 0; i < 4; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
          out[4 * i + j] = state[j].alpha[i];
      }
   }
}

/**********************************************************************************************
BLOCK-DECRYPTION-AES
**********************************************************************************************/
void blockDecryptionAes(byte in[], byte *out, word *w, int Nb, int Nr, int Nk)
{

   word state[4];

      for(int i = 0; i < 4; ++i)
      {
         for(int j = 0; j < 4; ++j)
         {
            state[j].alpha[i] = in[4 * i + j];        
         }
      }

   addRoundKey(state, w, Nr*Nb, (Nr+1)*Nb-1);

   for(int rnd = Nr-1; rnd > 0; --rnd)
    {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, w, rnd*Nb, (rnd+1)*Nb-1);
      invMixColumns(state);           
   }

   invShiftRows(state);
   invSubBytes(state);
   addRoundKey(state, w, 0, Nb-1);

   for(int i = 0; i < 4; ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
          out[4 * i + j] = state[j].alpha[i];
      }
   }
}

/**********************************************************************************************
AES-ENCRYPTION CALLING FUNCTION
**********************************************************************************************/
byte* aesEncryption(byte key[], byte plain[], int Nk, int Nb, int Nr)
{
   byte *out = (byte *) malloc((4 * Nb) * sizeof(byte));
   word *w = (word *) malloc(Nb * (Nr + 1) * sizeof(word));
   word *expanded_key = (word *) malloc(Nb * (Nr + 1) * sizeof(word));

   keyExpansion(key, w, Nk, Nb, Nr);

   for(int i = 0; i < Nb * (Nr + 1); ++i)
   {
         for(int j = 0; j < 4; ++j)
      {
         expanded_key[i].alpha[j] = w[(i / Nb) * Nb + j].alpha[i % Nb];
      }     
   }
   blockEncryptionAes(plain, out, expanded_key, Nb, Nr, Nk);

   return out;
}

/**********************************************************************************************
AES-DECRYPTION CALLING FUNCTION
**********************************************************************************************/
byte* aesDecryption(byte key[], byte cipher[], int Nk, int Nb, int Nr)
{
   byte *out = (byte *) malloc((4 * Nb) * sizeof(byte));
   word *w = (word *) malloc(Nb * (Nr + 1) * sizeof(word));
   word *expanded_key = (word *) malloc(Nb * (Nr + 1) * sizeof(word));

   keyExpansion(key, w, Nk, Nb, Nr);

   for(int i = 0; i < Nb * (Nr + 1); ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         expanded_key[i].alpha[j] = w[(i / Nb) * Nb + j].alpha[i % Nb];
      }     
   }

   blockDecryptionAes(cipher, out, expanded_key, Nb, Nr, Nk);

   return out;
}



/********************************************************************************************************
AES ENCRYPTION CBC INTERNAL FUNCTION
**********************************************************************************************************/

byte* aesEncryptionCBC(byte key[], byte plain[], byte iv[], int Nk, int Nb, int Nr, int numBytes)
{
   byte *out = (byte *) malloc((numBytes + 4 * Nb) * sizeof(byte));
   byte *tempPlain = (byte *) malloc(numBytes * sizeof(byte));
   word *w = (word *) malloc(Nb * (Nr + 1) * sizeof(word));
   word *expanded_key = (word *) malloc(Nb * (Nr + 1) * sizeof(word));

   // Copying plain into tempPlain
   for(int k = 0; k < numBytes; ++k)
   {
      tempPlain[k] = plain[k];
   }

   keyExpansion(key, w, Nk, Nb, Nr);

   for(int i = 0; i < Nb * (Nr + 1); ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         expanded_key[i].alpha[j] = w[(i / Nb) * Nb +j].alpha[i % Nb];
      }
   }

   for(int l = 0; l < 4 * Nb; ++l)
   {
      out[l] = iv[l];
   }

   for(int i = 0; i < numBytes; i += 4 * Nb)
   {
      for(int j = 0; j < 4 * Nb; ++j)
      {
         tempPlain[i + j] ^= out[i + j];
      }
      blockEncryptionAes(tempPlain + i, out + i + 4 * Nb, expanded_key, Nb, Nr, Nk);
   }
   return out;
}

/******************************************************************************************************
AES ENCRYPTION CBC MODE FOR CALLING
*******************************************************************************************************/
byte* aesEncryptionCBC_Mode(byte key[], byte plain[], byte iv[], int Nk, int Nb, int Nr, int numBytes)
{
   byte *out;

   if(numBytes % (4 * Nb) == 0)
   {
      byte *tempPlain = (byte *) malloc((numBytes + 4 * Nb) * sizeof(int));
      for(int i = 0; i < numBytes + 4 * Nb; ++i)
      {
         if(i < numBytes)
         {
            tempPlain[i] = plain[i];
         }
         else
         {
            tempPlain[i] = 0x10;     // int value is 16
         }
      }
      out = aesEncryptionCBC(key, tempPlain, iv, Nk, Nb, Nr, numBytes + 4 * Nb);      
   }
   else
   {
      byte *tempPlain = (byte *) malloc(((numBytes - 1) / (4 * Nb) + 1) * 4 * Nb * sizeof(int));
      for(int i = 0; i < ((numBytes - 1) / (4 * Nb) + 1) * 4 * Nb; ++i)
      {
         if(i < numBytes)
         {
            tempPlain[i] = plain[i];
         }
         else
         {
            tempPlain[i] = (byte)(((numBytes - 1) / (4 * Nb) + 1) * 4 * Nb - numBytes);
         }printf("%x ", tempPlain[i]);
      }printf("\n");
      out = aesEncryptionCBC(key, tempPlain, iv, Nk, Nb,  Nr, ((numBytes - 1) / (4 * Nb) + 1) * 4 * Nb );  
   }
   return out;
}

/*************************************************************************************************************
AES DECRYPTION CBC INTERNAL FUNCTION
*************************************************************************************************************/
byte* aesDecryptionCBC(byte key[], byte cipher[], int Nk, int Nb, int Nr, int numBytes)
{
   byte *tempCipher = (byte *) malloc(numBytes * sizeof(byte));
   byte *out = (byte *) malloc((numBytes - 4 * Nb) * sizeof(byte));
   word *w = (word *) malloc(Nb * (Nr + 1) * sizeof(word));
   word *expanded_key = (word *) malloc(Nb * (Nr + 1) * sizeof(word));
   byte *out1;

   for(int k = 0; k < numBytes; ++k)
   {
      tempCipher[k] = cipher[k];
   }

   keyExpansion(key, w, Nk, Nb, Nr);

   for(int i = 0; i < Nb * (Nr + 1); ++i)
   {
      for(int j = 0; j < 4; ++j)
      {
         expanded_key[i].alpha[j] = w[(i / Nb) * Nb +j].alpha[i % Nb];
      }
   }

   for(int i = 0; i < numBytes - 4 * Nb; i += 4 * Nb)
   {
      out1 = aesDecryption(key, tempCipher + i + 4 * Nb, Nk, Nb, Nr);

      for(int j = 0; j < 4 * Nb; ++j)
      {
         out[i + j] = out1[j] ^ tempCipher[i + j];
      }
   }
   return out;
}
int numLastBytesRemove = 0;
/*************************************************************************************************************
AES DECRYPTION CBC MODE FOR CALLING
*************************************************************************************************************/
byte* aesDecryptionCBC_Mode(byte key[], byte cipher[], int Nk, int Nb, int Nr, int numBytes)
{
   byte *out, *result;

   out = aesDecryptionCBC(key, cipher, Nk, Nb, Nr, numBytes);

   result = (byte *) malloc((numBytes - 4 * Nb - ((int)out[numBytes - 4 * Nb - 1])) * sizeof(byte));

   for(int i = 0; i < numBytes - 4 * Nb - ((int)out[numBytes - 4 * Nb - 1]); ++i)
   {
      result[i] = out[i];
   }
   
   numLastBytesRemove = ((int)out[numBytes - 4 * Nb - 1]);

   return result;
}

#if 0
/*************************************************************************************************************
For testing purpose only
*************************************************************************************************************/
int main()
{
	byte key[] = {0x14,0x0b,0x41,0xb2,0x2a,0x29,0xbe,0xb4,0x06,0x1b,0xda,0x66,0xb6,0x74,0x7e,0x14};
	byte cipher[] = {0x5b,0x68,0x62,0x9f,0xeb,0x86,0x06,0xf9,0xa6,0x66,0x76,0x70,0xb7,0x5b,0x38,0xa5,0xb4,0x83,0x2d,0x0f,0x26,0xe1,0xab,0x7d,
					0xa3,0x32,0x49,0xde,0x7d,0x4a,0xfc,0x48,0xe7,0x13,0xac,0x64,0x6a,0xce,0x36,0xe8,0x72,0xad,0x5f,0xb8,0xa5,0x12,0x42,0x8a,
					0x6e,0x21,0x36,0x4b,0x0c,0x37,0x4d,0xf4,0x55,0x03,0x47,0x3c,0x52,0x42,0xa2,0x53};
   byte cipher2[] = {0x56,0x2e,0x17,0x99,0x6d,0x09,0x3d,0x28,0xdd,0xb3,0xba,0x69,0x5a,0x2e,0x6f,0x58,0xd2,0x96,0xcd,0x94,0xc2,0xcc,0xcf,0x8a,
                     0x3a,0x86,0x30,0x28,0xb5,0xe1,0xdc,0x0a,0xa7,0x30,0xc2,0x8c,0xfa,0x1c,0x51,0xfd,0x96,0xe5,0x19,0x35,0xe2,0x94,0xe6,0x9b};
   byte plain[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e};
   byte iv[] = {0x56,0x2e,0x17,0x99,0x6d,0x09,0x3d,0x28,0xdd,0xb3,0xba,0x69,0x5a,0x2e,0x6f,0x58};
	byte *out1 = NULL, *out2 = NULL;
	char *keyString, *plainText;
	int Nk, Nb, Nr;

	printf("Enter Values of Nk, Nb, Nr : ");
	scanf("%d%d%d", &Nk, &Nb, &Nr);

	

   out1 = aesEncryptionCBC_Mode(key, plain,iv, Nk, Nb, Nr, 31);
    

	for(int i = 0; i < 32 + 4*Nb; ++i)
	{
		printf("%x", out1[i]);
      if(int(out1[i]) <= 15)printf("here");
      if((i + 1)% (4 * Nb) == 0)
         printf("\n");
	}

 out2 = aesDecryptionCBC_Mode(key, cipher, Nk, Nb, Nr, 64);
   for(int i = 0; i < 64 - 4 * Nb - numLastBytesRemove; ++i)
   {
      printf("%c", out2[i]);
      
   }
   printf("\n");
	return 0;
}
#endif