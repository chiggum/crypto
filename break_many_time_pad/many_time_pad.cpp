#include <cstdio>
#include <cstdlib>
#include <iostream>


/*

----Concept to be followed----
-function to convert hex to char                        DONE
-function to convert char to hex                        DONE
-function to convert hex string to char string          DONE
-function to convert char string to hex                 DONE
-funtion to xor two hex strings and return the result   DONE

- After creating above functions, Cryptanalysis is performed and the analysis is saved in CryptAnalysis.txt
*/



char hex_to_char(char *s)
{
	int x = 0;
	// s[0]*16 + s[1] is the reqd int value
	if(s[0] == '0') x += 16 * 0;
	if(s[0] == '1') x += 16 * 1;
	if(s[0] == '2') x += 16 * 2;
	if(s[0] == '3') x += 16 * 3;
	if(s[0] == '4') x += 16 * 4;
	if(s[0] == '5') x += 16 * 5;
	if(s[0] == '6') x += 16 * 6;
	if(s[0] == '7') x += 16 * 7;
	if(s[0] == '8') x += 16 * 8;
	if(s[0] == '9') x += 16 * 9;
	if(s[0] == 'a') x += 16 * 10;
	if(s[0] == 'b') x += 16 * 11;
	if(s[0] == 'c') x += 16 * 12;
	if(s[0] == 'd') x += 16 * 13;
	if(s[0] == 'e') x += 16 * 14;
	if(s[0] == 'f') x += 16 * 15;

	if(s[1] == '0') x += 0;
	if(s[1] == '1') x += 1;
	if(s[1] == '2') x += 2;
	if(s[1] == '3') x += 3;
	if(s[1] == '4') x += 4;
	if(s[1] == '5') x += 5;
	if(s[1] == '6') x += 6;
	if(s[1] == '7') x += 7;
	if(s[1] == '8') x += 8;
	if(s[1] == '9') x += 9;
	if(s[1] == 'a') x += 10;
	if(s[1] == 'b') x += 11;
	if(s[1] == 'c') x += 12;
	if(s[1] == 'd') x += 13;
	if(s[1] == 'e') x += 14;
	if(s[1] == 'f') x += 15;

	return (char)x;
}

char* char_to_hex(char c)
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

char* charString_to_hexString(char *s)
{
	int length = 0;
	char *x;
	char *y = s;

	while(*y != '\0')
	{
		length += 1;
		y += 1;
	}

	x = (char *) malloc((2 * length + 1) * sizeof(char));

	y = s;  // shifting the address to the original string

	for(int i = 0; i < length; ++i)
	{
	    sprintf(x + 2 * i, "%s", char_to_hex(y[i]));
	}
	
	x[2 * length] = '\0';   // making last element null character

	return x;
}

char* hexString_to_charString(char* s)
{
	int length = 0;
	char *x;
	char *y = s;

	while(*y != '\0')
	{
		length += 1;
		y += 1;
	}

	x = (char *) malloc((length / 2 + 1) * sizeof(char));

	y = s;

	for(int i = 0; i < length / 2; ++i)
	{
	    sprintf(x + i, "%c", hex_to_char(y + 2*i));
	}

	x[length / 2] = '\0';

	return x;
}

int to_hex(char c)
{
	int x;

	if(c == '0') x = 0x0;
	if(c == '1') x = 0x1;
	if(c == '2') x = 0x2;
	if(c == '3') x = 0x3;
	if(c == '4') x = 0x4;
	if(c == '5') x = 0x5;
	if(c == '6') x = 0x6;
	if(c == '7') x = 0x7;
	if(c == '8') x = 0x8;
	if(c == '9') x = 0x9;
	if(c == 'a') x = 0xa;
	if(c == 'b') x = 0xb;
	if(c == 'c') x = 0xc;
	if(c == 'd') x = 0xd;
	if(c == 'e') x = 0xe;
	if(c == 'f') x = 0xf;

	return (int)x;
}

char to_char(int c)
{
	char x;

	if(c == 0x0) x = '0';
	if(c == 0x1) x = '1';
	if(c == 0x2) x = '2';
	if(c == 0x3) x = '3';
	if(c == 0x4) x = '4';
	if(c == 0x5) x = '5';
	if(c == 0x6) x = '6';
	if(c == 0x7) x = '7';
	if(c == 0x8) x = '8';
	if(c == 0x9) x = '9';
	if(c == 0xa) x = 'a';
	if(c == 0xb) x = 'b';
	if(c == 0xc) x = 'c';
	if(c == 0xd) x = 'd';
	if(c == 0xe) x = 'e';
	if(c == 0xf) x = 'f';

	return x;
}

char xor_chars(char a, char b)
{
	return to_char(to_hex(a) ^ to_hex(b));
}

char* xor_hexStrings(char *a, char *b)
{
	char *x = a, *y = b, *z;
	int length_a = 0, length_b = 0, i = 0;

	while(*x != '\0')
	{
		length_a += 1;
		x += 1;
	}
	while(*y != '\0')
	{
		length_b += 1;
		y += 1;
	}
	if(length_a == length_b)
	{
		z = (char *) malloc((length_a + 1) * sizeof(char));
		for(i = 0; i < length_a; ++i)
		{
			z[i] = xor_chars(a[i], b[i]);
		}
		z[i] = '\0';  // here i == length_a == length_b
	}
	else if(length_a > length_b)
	{
		z = (char *) malloc((length_a + 1) * sizeof(char));
		for(i = 0; i < length_a; ++i)
		{
			if(i < length_b)
			    z[i] = xor_chars(a[i], b[i]);
			else
				z[i] = a[i];
		}
		z[i] = '\0';  // i == length_a
	}
	else
	{
		z = (char *) malloc((length_b + 1) * sizeof(char));
		for(i = 0; i < length_b; ++i)
		{
			if(i < length_a)
			    z[i] = xor_chars(a[i], b[i]);
			else
				z[i] = b[i];
		}
		z[i] = '\0';  // i == length_b
	}
	return z;
}

int main()
{
	FILE *fp = fopen("CryptAnalysis.txt", "a");
	char *p[11], *key;

	// Folowing are 11 CipherTexts and the last one is the target ciphertext reqd. to be decrypted

	p[0] = "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e";
	p[1] = "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f";
	p[2] = "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb";
	p[3] = "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa";
	p[4] = "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070";
	p[5] = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4";
	p[6] = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce";
	p[7] = "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3";
	p[8] = "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027";
	p[9] = "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83";
	p[10] = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";

    
    /* XORING EVERY PAIR OF CIPHERTEXT

        fprintf(fp,"xoring every pair\n\n");
    
        for(int i = 0; i < 11; ++i)
        {
        	for(int j = 0; j < 11; ++j)
        	{
        		fprintf(fp, "%d--%d\n", i, j);
        	    fprintf(fp, "%s\n\n", xor_hexStrings(p[i],p[j]));
        	}
    
        }
    */

    /* THE FIRST FOUR CHARACTERS OF P[5], P[6], P[10] SEEMS TO BE "the " VIA ENGLISH WORD FREQUENCY ANALYSIS */


	/* USING ABOVE ASSUMPTION, FINDING THE FIRST FOUR KEY HEX CHARACTERS

	    fprintf(fp, "%s\n\n", xor_hexStrings(charString_to_hexString("the "),p[10]));
	*/

    key = "46396e89";   // this is the first four hex of assumed key


    /* MAKING A TABLE OF XORS OF ALL ALPHABETIC CHARACTERS I.E. a-z
        for(int i = 97; i < 123; ++i)
        {
        	for(int j = 97; j < 123; ++j)
        	{
        		fprintf(fp, "%s ", xor_hexStrings(char_to_hex((char)i), char_to_hex((char)j)));
        	}
        	fprintf(fp,"\n");
        }
    */

	/* PRINTING THE CTs USING ASSUMED KEY
	    for(int i = 0; i < 11; ++i)
	    {
	    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
	    }
	*/

    /* USING ENGLISH WORDS MATCHING PREDICTING THE CHARACTERS
    Prediction : 5th character of
                     ciphertext 0, 7 = a,   a8  == 61
                                1 = r,      bb  == 72
                                5, 6 = e    ac  == 65
    */

	/*  GETTING HEX VALUE OF THE NEXT KEY CHARACTER
	    fprintf(fp, "%s\n\n", xor_hexStrings("a8", "61"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("a8", "41"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("bb", "72"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("bb", "52"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("ac", "65"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("ac", "45"));
    */

    /* 5th KEY HEX CAME OUT TO BE = c9 */

    key = "46396e89c9";

	/* PRINTING THE CTs USING ASSUMED KEY

	    for(int i = 0; i < 11; ++i)
	    {
	    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
	    }
	*/

    /* USING ENGLISH WORDS MATCHING PREDICTING THE CHARACTERS
       Prediction : 6th character of
                             ciphertext  0, 7 == n == 6e  == b5
                                         5, 6 == ' ' == 20  === fb
    */

    
	/*  GETTING HEX VALUE OF THE NEXT KEY CHARACTER

		fprintf(fp, "%s\n\n", xor_hexStrings("6e", "b5"));
	    fprintf(fp, "%s\n\n", xor_hexStrings("20", "fb"));
	*/

    /*  6th KEY HEX CAME OUT TO BE = db */

	key = "46396e89c9db"  ; 
	
	/* PRINTING THE CTs USING ASSUMED KEY

    for(int i = 0; i < 11; ++i)
    {
    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
    }
	*/

    /* IN p[3], IT SEEMS THAT PLAIN TEXT IS  "the cipher"
       lets see
        predicting 7th character as p == 70 == a8
	*/
    
    // fprintf(fp, "%s\n\n", xor_hexStrings("70", "a8"));

    /*7th KEY HEX CAME OUT TO BE = d8*/

    key = "46396e89c9dbd8";
 
    /*  PRINTING THE CTs USING ASSUMED KEY

    for(int i = 0; i < 11; ++i)
    {
    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
    }
    */

    /*
     predicting p[3] = "the cipher"

    i.e. for p[3] 8th char == h  === 68 == a4
                  9th char == e === 65 == fd
                  10th char == r === 72 == 06
    */

    /* 

        fprintf(fp, "%s\n\n", xor_hexStrings("68", "a4"));
        fprintf(fp, "%s\n\n", xor_hexStrings("65", "fd"));
        fprintf(fp, "%s\n\n", xor_hexStrings("72", "06"));
    */

    key = "46396e89c9dbd8cc9874";
    
    /* 
    for(int i = 0; i < 11; ++i)
    {
    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
    }
     */ 

    // P[1] 11TH IS d == 64 == a3

    // fprintf(fp, "%s\n\n", xor_hexStrings("64", "51"));

    key = "46396e89c9dbd8cc987435";
    
    /* 
    for(int i = 0; i < 11; ++i)
    {
    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
    }
    */
 
    /*
    prediction p[3] is surely "the ciphertext"
    
    i.e. for p[3] 12th char == e  === 65 == 4f
                  13th char == x === 78 == b5
                  14th char == t === 74 == 17
    */
    
    /*             
    fprintf(fp, "%s\n\n", xor_hexStrings("65", "4f"));
    fprintf(fp, "%s\n\n", xor_hexStrings("78", "b5"));
    fprintf(fp, "%s\n\n", xor_hexStrings("74", "17"));
    */

    key = "46396e89c9dbd8cc9874352acd63";
	/*
	    for(int i = 0; i < 11; ++i)
	    {
	    	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
	    }
	*/

    /* p[10] is "the secret message "

      15th char == s == 73 == e6
      16th char == a == 61 == 71
      17th char == g == 67 == 49
      18th char == e == 65 == ca
      19th char == ' ' == 20 == ee
    */

    /* 
      fprintf(fp, "%s\n\n", xor_hexStrings("73", "e6"));
      fprintf(fp, "%s\n\n", xor_hexStrings("61", "71"));
      fprintf(fp, "%s\n\n", xor_hexStrings("67", "49"));
      fprintf(fp, "%s\n\n", xor_hexStrings("65", "ca"));
      fprintf(fp, "%s\n\n", xor_hexStrings("20", "ee"));
    */

    key = "46396e89c9dbd8cc9874352acd6395102eafce";

    /*
        for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
	*/
  
    /*
      PREDICTING p[5] = p[6] = "there are two types of "

      20th char == ' ' == 20 == 58
      21th char == o == 6f == c5
      22th char == f == 66 == 19
      23th char == ' ' == 20 == cd
	*/
  
   /* 
    fprintf(fp, "%s\n\n", xor_hexStrings("20", "58"));
      fprintf(fp, "%s\n\n", xor_hexStrings("6f", "c5"));
      fprintf(fp, "%s\n\n", xor_hexStrings("66", "19"));
      fprintf(fp, "%s\n\n", xor_hexStrings("20", "cd"));
    */
      key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed";
/*great
      for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/

/* p[0] = "we can factor the number "
  24th char == r == 72 == 5a
      25th char == ' ' == 20 == 80
*/
//fprintf(fp, "%s\n\n", xor_hexStrings("72", "5a"));
 //     fprintf(fp, "%s\n\n", xor_hexStrings("20", "80"));


key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a0";

/*for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/
        /*p[1] = "euler would probably enjoy "

        26th char == y == 79 == 06
        27th char == ' ' == 20 == 4b
*/
//fprintf(fp, "%s\n\n", xor_hexStrings("79", "06"));
  //    fprintf(fp, "%s\n\n", xor_hexStrings("20", "4b"));

      key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6b";

/*for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/
        /*p[10] = "the secret message is: When "
        28th char = ' ' == 20 == e9
*/
//fprintf(fp, "%s\n\n", xor_hexStrings("20", "e9"));

    key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc9";

/*for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/
        /*
          p[5] = "there are two types of cryptography "
          29 == o == 6f == e2
          30 == g == 67 == 4e
          31 == r == 72 == b7
          32 == a == 61 == 6a
          33 == p == 70 == 19
          34 == h == 68 == d8
          35 == y == 79 == 4a
          36 == ' ' == 20 == ba
        */
     /*     fprintf(fp, "%s\n\n", xor_hexStrings("6f", "e2"));
          fprintf(fp, "%s\n\n", xor_hexStrings("67", "4e"));
          fprintf(fp, "%s\n\n", xor_hexStrings("72", "b7"));
          fprintf(fp, "%s\n\n", xor_hexStrings("61", "6a"));
          fprintf(fp, "%s\n\n", xor_hexStrings("70", "19"));
          fprintf(fp, "%s\n\n", xor_hexStrings("68", "d8"));
          fprintf(fp, "%s\n\n", xor_hexStrings("79", "4a"));
          fprintf(fp, "%s\n\n", xor_hexStrings("20", "ba"));
*/

    key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a";

/*
for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/

       /*
       
       p[7] = "we can see the point where the chip is unhappy if a wrong "
       37 == i  == 69 == 
       38 == s  == 73 == 70
       39 == ' ' == 20 == 8b
       40 == u == 75 == 8a
       41 == n == 6e == 35
       42 == h == 68 == 74
       43 == a == 61 == f4
       44 == p == 70 == 0c
       45 == p == 70 == 00
       46 == y == 79 == ff
       47 == ' ' == 20 == f9
       48 == i == 69 == e0
       49 == f == 66  == 0f
       50 == ' ' == 20 == a1
       51 == a == 61 == 43
       52 == ' ' == 20 == 9f
       53 == w == 77 == d0
       54 == r == 72 == 65
       55 == o == 6f == 43
       56 == n == 6e == 27
       57 == g == 67 == a3
       58 == ' ' == 20 == bf
                          c8

*/
 /*      fprintf(fp, "%s", xor_hexStrings("69", "70"));
          fprintf(fp, "%s", xor_hexStrings("73", "8b"));
          fprintf(fp, "%s", xor_hexStrings("20", "8a"));
          fprintf(fp, "%s", xor_hexStrings("75", "35"));
          fprintf(fp, "%s", xor_hexStrings("6e", "74"));
          fprintf(fp, "%s", xor_hexStrings("68", "f4"));
          fprintf(fp, "%s", xor_hexStrings("61", "0c"));
          fprintf(fp, "%s", xor_hexStrings("70", "00"));
          fprintf(fp, "%s", xor_hexStrings("70", "ff"));
          fprintf(fp, "%s", xor_hexStrings("79", "f9"));
          fprintf(fp, "%s", xor_hexStrings("20", "e0"));
          fprintf(fp, "%s", xor_hexStrings("69", "0f"));
          fprintf(fp, "%s", xor_hexStrings("66", "a1"));
          fprintf(fp, "%s", xor_hexStrings("20", "43"));
          fprintf(fp, "%s", xor_hexStrings("61", "9f"));
          fprintf(fp, "%s", xor_hexStrings("20", "d0"));
          fprintf(fp, "%s", xor_hexStrings("77", "65"));
          fprintf(fp, "%s", xor_hexStrings("72", "43"));
          fprintf(fp, "%s", xor_hexStrings("6f", "27"));
          fprintf(fp, "%s", xor_hexStrings("6e", "a3"));
          fprintf(fp, "%s", xor_hexStrings("67", "bf"));
          fprintf(fp, "%s\n\n", xor_hexStrings("20", "c8"));

*/
    key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e8";
/*
for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }
*/
        /*
       
       p[7] = "we can see the point where the chip is unhappy if a wrong bit is sent and "
       59 == b == 62 == 60
       60 == i == 69 == b9
       61 == t == 74 == 2f
       62 == ' ' == 20 == 89
       63 == i == 69 == ee
       64 == s == 73 == 04
       65 == ' ' == 20 == 13
       66 == s == 73 == 2e
       67 == e == 65 == cb
       68 == n == 6e == 92
       69 == t == 74 == 98
       70 == ' ' == 20 == f5
       71 == a == 61 == fd
       72 == n == 6e == 2d
       73 == d == 64 == 5e
       74 == ' ' == 20 == 4b

*/
    /*
    fprintf(fp, "%s", xor_hexStrings("62", "60"));
    fprintf(fp, "%s", xor_hexStrings("69", "b9"));
    fprintf(fp, "%s", xor_hexStrings("74", "2f"));
    fprintf(fp, "%s", xor_hexStrings("20", "89"));
    fprintf(fp, "%s", xor_hexStrings("69", "ee"));
    fprintf(fp, "%s", xor_hexStrings("73", "04"));
    fprintf(fp, "%s", xor_hexStrings("20", "13"));
    fprintf(fp, "%s", xor_hexStrings("73", "2e"));
    fprintf(fp, "%s", xor_hexStrings("65", "cb"));
    fprintf(fp, "%s", xor_hexStrings("6e", "92"));
    fprintf(fp, "%s", xor_hexStrings("74", "98"));
    fprintf(fp, "%s", xor_hexStrings("20", "f5"));
    fprintf(fp, "%s", xor_hexStrings("61", "fd"));
    fprintf(fp, "%s", xor_hexStrings("6e", "2d"));
    fprintf(fp, "%s", xor_hexStrings("64", "5e"));
    fprintf(fp, "%s", xor_hexStrings("20", "4b"));
    */

         
    key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b";
    /*    for(int i = 0; i < 11; ++i)
            {
            	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
            }
    */

    /*       
    p[7] = "we can see the point where the chip is unhappy if a wrong bit is sent and consumes more power "
    75 == c == 63 == 45
    76 == o == 6f == e4
    77 == n == 6e == 0e
    78 == s == 73 == cc
    79 == u == 75 == 3b
    80 == m == 6d == 9d
    81 == e == 65 == 59
    82 == s == 73 == e9
    83 ==   == 20 == 41
    84 == m == 6d == 7d
    85 == o == 6f == f7
    86 == r == 72 == c9
    87 == e == 65 == 5b
    88 ==   == 20 == ba
    89 == p == 70 == 41
    90 == o == 6f == 0e
    91 == w == 77 == 9a
    92 == e == 65 == a2
    93 == r == 72 == ca
    94 ==   == 20 == 24
    */

    /* 
    fprintf(fp, "%s", xor_hexStrings("63", "45"));
    fprintf(fp, "%s", xor_hexStrings("6f", "e4"));
    fprintf(fp, "%s", xor_hexStrings("6e", "0e"));
    fprintf(fp, "%s", xor_hexStrings("73", "cc"));
    fprintf(fp, "%s", xor_hexStrings("75", "3b"));
    fprintf(fp, "%s", xor_hexStrings("6d", "9d"));
    fprintf(fp, "%s", xor_hexStrings("65", "59"));
    fprintf(fp, "%s", xor_hexStrings("73", "e9"));
    fprintf(fp, "%s", xor_hexStrings("20", "41"));
    fprintf(fp, "%s", xor_hexStrings("6d", "7d"));
    fprintf(fp, "%s", xor_hexStrings("6f", "f7"));
    fprintf(fp, "%s", xor_hexStrings("72", "c9"));
    fprintf(fp, "%s", xor_hexStrings("65", "5b"));
    fprintf(fp, "%s", xor_hexStrings("20", "ba"));
    fprintf(fp, "%s", xor_hexStrings("70", "41"));
    fprintf(fp, "%s", xor_hexStrings("6f", "0e"));
    fprintf(fp, "%s", xor_hexStrings("77", "9a"));
    fprintf(fp, "%s", xor_hexStrings("65", "a2"));
    fprintf(fp, "%s", xor_hexStrings("72", "ca"));
    fprintf(fp, "%s", xor_hexStrings("20", "24"));
    */

          key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a611098bb3e9a3161edc7b804";  

    for(int i = 0; i < 11; ++i)
        {
        	fprintf(fp, "%d---%s\n\n\n",i,hexString_to_charString(xor_hexStrings(key, p[i])));
        }

    // Sufficient to get answer :
    key = "46396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a61";

    fprintf(fp, "Answer---%s\n\n\n",hexString_to_charString(xor_hexStrings(key, p[10])));

	fclose(fp);
  
	return 0;
}
