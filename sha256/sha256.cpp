/*
Going to do an actual implementation of this in php
*/

#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>

using namespace std;

string GetBinaryStringFromHexString (string sHex)
{
	string sReturn = "";
	for (int i = 0; i < sHex.length (); ++i)
	{
		switch (sHex [i])
		{
			case '0': sReturn.append ("0000"); break;
			case '1': sReturn.append ("0001"); break;
			case '2': sReturn.append ("0010"); break;
			case '3': sReturn.append ("0011"); break;
			case '4': sReturn.append ("0100"); break;
			case '5': sReturn.append ("0101"); break;
			case '6': sReturn.append ("0110"); break;
			case '7': sReturn.append ("0111"); break;
			case '8': sReturn.append ("1000"); break;
			case '9': sReturn.append ("1001"); break;
			case 'a': sReturn.append ("1010"); break;
			case 'b': sReturn.append ("1011"); break;
			case 'c': sReturn.append ("1100"); break;
			case 'd': sReturn.append ("1101"); break;
			case 'e': sReturn.append ("1110"); break;
			case 'f': sReturn.append ("1111"); break;
		}
	}
	return sReturn;
}

string GetHexStringFromBinaryString (string s)
{
	string sReturn = "";
	for (int i = 0; i < s.length (); i+=4)
	{
			if(s[i] == '0' && s[i + 1] == '0' && s[i + 2] == '0' && s[i+3] == '0') 
				{
					sReturn.append("0");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '0' && s[i + 2] == '0' && s[i+3] == '1') 
				{
					sReturn.append("1");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '0' && s[i + 2] == '1' && s[i+3] == '0') 
				{
					sReturn.append("2");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '0' && s[i + 2] == '1' && s[i+3] == '1') 
				{
					sReturn.append("3");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '1' && s[i + 2] == '0' && s[i+3] == '0') 
				{
					sReturn.append("4");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '1' && s[i + 2] == '0' && s[i+3] == '1') 
				{
					sReturn.append("5");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '1' && s[i + 2] == '1' && s[i+3] == '0') 
				{
					sReturn.append("6");
					continue;
				}
			if(s[i] == '0' && s[i + 1] == '1' && s[i + 2] == '1' && s[i+3] == '1') 
				{
					sReturn.append("7");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '0' && s[i + 2] == '0' && s[i+3] == '0') 
				{
					sReturn.append("8");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '0' && s[i + 2] == '0' && s[i+3] == '1') 
				{
					sReturn.append("9");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '0' && s[i + 2] == '1' && s[i+3] == '0') 
				{
					sReturn.append("a");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '0' && s[i + 2] == '1' && s[i+3] == '1') 
				{
					sReturn.append("b");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '1' && s[i + 2] == '0' && s[i+3] == '0') 
				{
					sReturn.append("c");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '1' && s[i + 2] == '0' && s[i+3] == '1') 
				{
					sReturn.append("d");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '1' && s[i + 2] == '1' && s[i+3] == '0') 
				{
					sReturn.append("e");
					continue;
				}
			if(s[i] == '1' && s[i + 1] == '1' && s[i + 2] == '1' && s[i+3] == '1') 
				{
					sReturn.append("f");
					continue;
				}
	}
	return sReturn;
}

char* char_to_hex(byte c)
{
	int x = 0;
	char *s = (char *) malloc(2 * sizeof(char));

	x = (int)c;

	// x / 16 is s[0] and s%16 = s[1]
	if(x / 16 == 0) s[0] = '0';
	if(x / 16 == 1) s[0] = '1';
	if(x / 16 == 2) s[0] = '2';
	if(x / 16 == 3) s[0] = '3';
	if(x / 16 == 4) s[0] = '4';
	if(x / 16 == 5) s[0] = '5';
	if(x / 16 == 6) s[0] = '6';
	if(x / 16 == 7) s[0] = '7';
	if(x / 16 == 8) s[0] = '8';
	if(x / 16 == 9) s[0] = '9';
	if(x / 16 == 10) s[0] = 'a';
	if(x / 16 == 11) s[0] = 'b';
	if(x / 16 == 12) s[0] = 'c';
	if(x / 16 == 13) s[0] = 'd';
	if(x / 16 == 14) s[0] = 'e';
	if(x / 16 == 15) s[0] = 'f';

	if(x % 16 == 0) s[1] = '0';
	if(x % 16 == 1) s[1] = '1';
	if(x % 16 == 2) s[1] = '2';
	if(x % 16 == 3) s[1] = '3';
	if(x % 16 == 4) s[1] = '4';
	if(x % 16 == 5) s[1] = '5';
	if(x % 16 == 6) s[1] = '6';
	if(x % 16 == 7) s[1] = '7';
	if(x % 16 == 8) s[1] = '8';
	if(x % 16 == 9) s[1] = '9';
	if(x % 16 == 10) s[1] = 'a';
	if(x % 16 == 11) s[1] = 'b';
	if(x % 16 == 12) s[1] = 'c';
	if(x % 16 == 13) s[1] = 'd';
	if(x % 16 == 14) s[1] = 'e';
	if(x % 16 == 15) s[1] = 'f';

	return s;
}

string charString_to_hexString(byte *s, int length)
{
	
	string x;
	byte *y = s;

	for(int i = 0; i < length; ++i)
	{
	    sprintf(&x[2*i], "%s", char_to_hex(y[i]));
	}
	
	x[2 * length] = '\0';   // making last element null character

	return x;
}


typedef unsigned char byte;

int main()
{
	FILE *fp = fopen("6 - 1 - Introduction (11 min).mp4", "rb");
	
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);

	int numBlocks, count, numLast, blockSize = 1024;
	
	if(size % blockSize != 0)
		numBlocks = size / blockSize + 1;
	else
		numBlocks = size / blockSize;

	count = numBlocks;
	numLast = size - (size / blockSize) * blockSize;

	byte* block;
	string encoded;
	string encodedString;
	string decoded;
	string result;
	CryptoPP::SHA256 hash;
	int x;

	while(count)
	{
		if(count == numBlocks)
		{
			x = numLast;
			block = (byte *) malloc(x * sizeof(byte));
		}
		if(count == numBlocks - 1)
		{
			x = blockSize;
			block = (byte *) realloc(block, x * sizeof(byte));
		}

		fseek(fp, (count - 1) * blockSize, SEEK_SET);
		fread(&block[0], sizeof(unsigned char), x, fp);

		encoded = charString_to_hexString(block, x);		
		encodedString.resize(x * 2);

		for(int i = 0; i < x * 2; ++i)
		{
			encodedString[i] =  encoded[i] ;
		}
		
		CryptoPP::StringSource sss(GetHexStringFromBinaryString(GetBinaryStringFromHexString(encodedString).append(GetBinaryStringFromHexString(result))), true,
			new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(decoded)
			) 
		); 

		result.clear();
	    CryptoPP::StringSource ss(decoded, true,
	        new CryptoPP::HashFilter(
	            hash, new CryptoPP::HexEncoder(
	                new CryptoPP::StringSink(result), false)
	        )
	    );

	    decoded.clear();
	    encodedString.clear();
	    encoded.clear();

	    count--;
	}
    
	cout << result << endl;

	return 0;

}