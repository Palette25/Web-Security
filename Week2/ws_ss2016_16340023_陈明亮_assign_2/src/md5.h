/*
* Program: md5.h
* Usage:
*	Provide md5-processor definition
*/
#ifndef MD5_H_
#define MD5_H_

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>

using namespace std;

#define F(x,y,z) ((x&y)|(~x&z))
#define G(x,y,z) ((x&z)|(y&~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y^(x|~z))
#define ROTATE_LEFT(x,n) ((x<<n)|(x>>(32-n)))
#define FF(a,b,c,d,x,s,ac) { a+=F(b,c,d)+x+ac; a=ROTATE_LEFT(a,s); a+=b;}
#define GG(a,b,c,d,x,s,ac) { a+=G(b,c,d)+x+ac; a=ROTATE_LEFT(a,s); a+=b;}
#define HH(a,b,c,d,x,s,ac) { a+=H(b,c,d)+x+ac; a=ROTATE_LEFT(a,s); a+=b;}
#define II(a,b,c,d,x,s,ac) { a+=I(b,c,d)+x+ac; a=ROTATE_LEFT(a,s); a+=b;}

struct MD5_Meta{
	unsigned char buffer[64];
	unsigned int state[4];
	unsigned int number[2];
};

class MD5_Processor{
public:
	MD5_Processor(string filePath);
	void MD5_Init();
	void MD5_Update(unsigned char* input, int len);
	void MD5_Transform(unsigned int* state, unsigned char* block);
	void MD5_Encode(unsigned char* out, unsigned int* in, int len);
	void MD5_Decode(unsigned int* out, unsigned char* in, int len);
	void MD5_Final();
	unsigned char* getPlainText(){
		return plainText;
	}


private:
	MD5_Meta meta;
	unsigned char plainText[50 * 1024];
	unsigned char cipherText[16];

};

#endif