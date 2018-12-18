/*
* Program: X509_Ce_Parse.h
* Usage: Read the X.509 Certificate binary input and Parse its content
*/
#ifndef X509_CE_PARSER_H
#define X509_CE_PARSER_H

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>

using namespace std;

// Definitions of certificate data structures
// 1. Basic numberal datas structures
struct Len{
	int length, tagNum;
	Len(int len_, int tag_){
		this->length = len_;
		this->tagNum = tag_;
	}
	Len(){
		this->length = 0;
		this->tagNum = 0;
	}
};

struct ShortTLV{
	char src1[50];
	char src2[50];
};

struct LongTLV{
	char src1[50];
	char src2[5000];
};

// 2. Signature infos datas structures
struct SignatureArray{
	char arr1[50];
	char arr2[50];
};

struct SignaturePublicKey{
	ShortTLV algorithm;
	ShortTLV parameters;
	LongTLV publicKey;
};

struct SignatureAlgorithm{
	ShortTLV algorithm;
	ShortTLV parameters;
};

struct SignatureValue{
	LongTLV value;
};

// 3. Certificate main content
struct TbsCertificate{
	SignatureAlgorithm Algorithm;
	SignaturePublicKey PublicKey;
	SignatureArray Issues[6];
	SignatureArray Subjects[6];
	// Basic Infos
	ShortTLV version;
	ShortTLV serialNum;
	ShortTLV validation[2];
	ShortTLV issueID;
	ShortTLV subjectID;
	ShortTLV extensions;
};

struct X509Certificate{
	TbsCertificate certificate;
	SignatureAlgorithm CAS_Algorithm;
	SignatureValue CAS_Value;
};

class CeParser{
public:
	CeParser(char* path);
	// Startup of parsing
	void startParsing();
	// Member tool functions
	void initMembers();
	Len TlvMatching();
	void fillBits(int length);
	void fillInfos(int turn);
	void writeResult(char* path);


private:
	string inputName;
	FILE* file;
	// signature members
	SignatureArray SA[7];
	SignatureArray IS[6];
	X509Certificate CA_Certificate;
	// Temp state variables
	int turn_num;
	int turn_temp;
	bool match_end;
	char state[5000];

};

#endif