/*
*******************************************************************************************************
AES ENCRYPTION AND DECRYPTION SCHEME Library IMPLMENTATION
****************************************************************************
Note on AES Encryption :
-- Original AES Encryption is same as ECB, except that there will always be one block of plain text encrypted with a unique / different key.
-- Note that we need to use NO PADDING feature OR Ignore the last block of cipher.
***********************************
No-Pdding Is not yet implemented
***********************************

Other Modes of AES Encryption are :
	Cipher-block chaining (CBC)
    Propagating cipher-block chaining (PCBC)
    Cipher feedback (CFB)
    Output feedback (OFB)
    Counter (CTR)

    NOTES ON FUNCTIONS / CLASSES USED IN THE PROGRAM :

    -- string.clear() : erases the content of a string which then becomes string of 0 characters i.e. length = 0

    --StringSource (const char *string, bool pumpAll, BufferedTransformation *attachment=NULL)
 	    (zero terminated string as source ) 
 	--StringSource (const byte *string, size_t length, bool pumpAll, BufferedTransformation *attachment=NULL)
   		(binary byte array as source )
 	--StringSource (const std::string &string, bool pumpAll, BufferedTransformation *attachment=NULL)
 		(std::string as source )

 		        -- pumpAll() : 
 		        {
 		        	Pump(). Pumps the specified number of bytes or until the end of the current message is encountered,
 		        	whichever comes first. If no argument is supplied, pumps until the end of the current message.
 		        	Does not call MessageEnd() on its attached transformation when the end of the message is encountered.
					
					pumpMessages(). Pumps the specified number of whole messages, or until there are no more messages,
					whichever comes first. If no argument is supplied, pumps until there are no more whole messages.
					Unless auto signal propagation has been disabled, PumpMessages() calls MessageEnd() on its attached
					transformation after the end of each message.
					
					PumpAll(). Pumps all messages just like PumpMessages() would if called with no argument, and then pumps
					the following uncomplete message until there is no more data to extract. With FileSource and StringSource, 
					PumpAll() extracts data like Pump() and then calls MessageEnd().
	
 		        }
    --A StreamTransformationFilter allows a Symmetric Cipher to particpate in Pipelining. The filter also handles details such as padding.

	-- HexEncoder Construction :

    HexEncoder(BufferedTransformation *attachment=NULL,
           bool uppercase=true,
           int outputGroupSize=0,
           const std::string &separator=":",
           const std::string &terminator="")

		-attachment is a BufferedTransformation, such as another filter or sink.
		-uppercase is an output formatting option and determines if output is uppercase or lowercase.
		-outputGroupSize is an output formatting option and determines the number of hexadecimal digit groups.
		 For example, if outputGroupSize = 4, then an output string is formatted as "FFEE:DDCC:BBAA:9988:7766:5544:3322:1100".
		-separator is a string used as a delimiter. The default is a colon, and a space (with a grouping of 4) will format the 
		 string as "FFEE DDCC BBAA 9988 7766 5544 3322 1100". Encoding a Binary String for C Output shows a slightly more interesting
		 use of the delimiter.
		-terminator adds a terminator to the output string. If outputGroupSize = 0, then a terminator of 'h' could be used 
		 to signify a hexadecimal string: "FFEEDDCCBBAA998877665544332211h".

	 -- AutoSeedRandomPool Pseudo random generator :
	 	// Scratch Area
		const unsigned int BLOCKSIZE = 16 * 8;
		byte pcbScratch[ BLOCKSIZE ];

		// Construction
		CryptoPP::AutoSeededRandomPool rng;

		// Random Block
		rng.GenerateBlock( pcbScratch, BLOCKSIZE );

	-- try {} catch {} catches specific exceptions caused during the execution of try block


*/

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::ECB_Mode;

#include "assert.h"

#define BLOCK_SIZE_BYTES 16   // This remains constant

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	//prng.GenerateBlock(key, sizeof(key));  /* For pseudo random key generation */

	byte plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	string cipher, encoded, recovered;

	/**************************************************************************************
	NOTE:
	***************************************************************************************
	-- plaintext can also be changed to type string of 16 bytes i.e. 16 characters
	-- Only Decryption can also be performed on the same basis
	****************************************************************************************/

	if(sizeof(key) != BLOCK_SIZE_BYTES || sizeof(plain) != BLOCK_SIZE_BYTES)
	{
		cerr << "Either plainText or Key has improper block size" << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));

		StringSource ss(plain, sizeof(plain), true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)//,
					//BlockPaddingScheme::NO_PADDING
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// print Cipher Text
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	encoded.resize(16*2);
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}
