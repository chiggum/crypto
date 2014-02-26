/***************************************************
HexEncoder/Decoder
***************************************************/
/*
*
*             STUDY THE WIKI FOR MORE INSIGHT
*
*
*/
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

typedef unsigned long long word64;

int main(int argc, char* argv[])
{
	/*********************************
	Non-Filter Method Encoder
	*********************************/
	#if 0
	byte decoded[] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	string encoded;
	HexEncoder encoder;
	encoder.Put(decoded, sizeof(decoded));
	encoder.MessageEnd();
	word64 size = encoder.MaxRetrievable();
	if(size)
	{
	encoded.resize(size);
	encoder.Get((byte*)encoded.data(), encoded.size());
	}
	cout << encoded << endl;
	#endif

	/*********************************
	Filter Method Encoder
	*********************************/
	#if 1
	char decoded[] = {106,102,114,97,103, 101, 9, 9,9, 9, 9, 9,9,9,9,114,101,32,83,113,117,101,97, 109,105,115,104,32,79,115,84,104,101,32,77,97,103,105,99,32,87,111,114,100,115,32};

	string encoded = "";
	StringSource ss(decoded, true/* pumpAll */,
		new HexEncoder(
			new StringSink(encoded), true
		) // HexEncoder
	); // StringSource
	cout << encoded << endl;
	//encoded = encoded + decoded;
	//cout << encoded << endl;
	#endif

	/*********************************
	Non-Filter Method Decoder
	*********************************/
	#if 0
	string encoded = "FFEEDDCCBBAA99887766554433221100";
	string decoded;
	HexDecoder decoder;
	decoder.Put( (byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();
	word64 size = decoder.MaxRetrievable();
	if(size && size <= SIZE_MAX)
	{
	decoded.resize(size);
	decoder.Get((byte*)decoded.data(), decoded.size());
	}
	cout << decoded << endl;
	#endif

	/*********************************
	Filter Method Decoder
	*********************************/
	#if 1
	//string encoded = "FFEEDDCCBBAA99887766554433221100";
	string decoded2;
	string enc = "3130362C3130322C3131342C39372C3130332C203130312C20392C20392C392C20392C20392C20392C392C392C392C3131342C3130312C33322C38332C3131332C3131372C3130312C39372C203130392C3130352C3131352C3130342C33322C37392C3131352C38342C3130342C3130312C33322C37372C39372C3130332C3130352C39392C33322C38372C3131312C3131342C3130302C3131352C3332";
	StringSource sss(enc, true/* pumpAll */,
		new HexDecoder(
			new StringSink(decoded2)
		) // HexEncoder
	); // StringSource
	cout << decoded2 << endl;
	#endif


	
	

	return 0;
	
}

