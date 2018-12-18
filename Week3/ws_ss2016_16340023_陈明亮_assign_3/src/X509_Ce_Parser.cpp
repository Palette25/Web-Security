/*
* Program: X509_Ce_Parser.cpp
* Usage: Implement Certificate Parser's methods
*/
#include "X509_Ce_Parser.h"

CeParser::CeParser(char* path){
	this->inputName = path;
	this->file = fopen(path, "rb");
	this->turn_num = 0;
	this->match_end = false;
}

void CeParser::startParsing(){
	// Binding init mappings
	initMembers();
	// Start TLV Matching
	TlvMatching();
	// Write result
	writeResult("../result/result.txt");
	// Final
	fclose(file);
}

// Member tool functions
void CeParser::initMembers(){
	// Fill all signature alogrithm mappings
	string names[8] = {"DSA", "sha1DSA", "RSA", "md2RSA", "md4RSA", "md5RSA", "sha1RSA", "sha256RSA"};
	string values[8] = {
		"1.2.840.10040.4.1", "1.2.840.10040.4.3", "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.2",  
		"1.2.840.113549.1.1.3", "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.11"
	};
	for(int i=0; i<8; i++){
		strcpy(this->SA[i].arr1, values[i].c_str());
		strcpy(this->SA[i].arr2, names[i].c_str());
	}
	// Fill all Info mappings
	string tnames[6] = {
		"Country ", "Sate or province name ", "Locality ", 
		"Organization name ", "Organizational Unit name ", "Common Name "
	};
	string tvalues[6] = {
		"2.5.4.6", "2.5.4.8", "2.5.4.7",
		"2.5.4.10", "2.5.4.11", "2.5.4.3"
	};
	for(int i=0; i<6; i++){
		strcpy(this->IS[i].arr1, tvalues[i].c_str());
		strcpy(this->IS[i].arr2, tnames[i].c_str());
	}
}

Len CeParser::TlvMatching(){
	if(this->match_end == true){
		return Len(1000, 0);
	}
	++this->turn_num;
	// Read type and length infos
	unsigned char uType = fgetc(file);
	unsigned char uLen = fgetc(file);
	int len = uLen, endLen = 0, temp, ttemp, i;
	char ts[20];
	bool fillFlag = true;
	unsigned char factor;
	// Start different infos matching
	if(uType < 0xa0){
		switch(uType){
			case 1: 
				factor = fgetc(file);
				if(factor == 0) strcpy(this->state, "FALSE");
				else strcpy(this->state, "TRUE");
				break;
			case 2:
			case 3:
			case 4:
				if(uLen > 0x80){
					temp = uLen - 0x80;
					len = 0;
					for(i=0; i<temp; i++){
						factor = fgetc(file);
						len = len * 256 + factor;
					}
				}
				fillBits(len);
				break;
			case 5:
				strcpy(this->state, "NULL");
				break;
			case 6:
				strcpy(this->state, "");
				factor = fgetc(file);
				ttemp = factor / 40;
				temp = uLen;
				sprintf(ts, "%d", ttemp);
				ttemp = factor - ttemp * 40;
				strcat(this->state, ts);  strcat(this->state, ".");
				sprintf(ts, "%d", ttemp); strcat(this->state, ts);
				for(i=1; i<temp; i++){
					strcat(this->state, ".");
					i--;
					ttemp = 0;
					while(true){
						factor = fgetc(file);
						i++;
						ttemp = ttemp * 128;
						if(factor & 0x80){
							ttemp += factor & 0x7f;
						}else {
							ttemp += factor;
							break;
						}
					}
					sprintf(ts, "%d", ttemp);
					strcat(this->state, ts);
				}
				break;
			case 0x13:
			case 0x17:
			case 0x18:
				temp = uLen;
				fread(this->state, 1, temp, file);
				state[temp] = '\0';
				break;
			case 0x30:
			case 0x31:
				fillFlag = false;
				if(uLen > 0x80){
					len = 0;  uLen = uLen - 0x80;
					for(i=0; i<uLen; i++){
						factor = fgetc(file);
						len = len * 256 + factor;
					}
				}
				temp = len;
				// Recursive invoking
				while(temp > 0){temp = temp - TlvMatching().length;}
				break;
			default:
				return Len();
		}
	}else {
		fillFlag = false;
		endLen = uType - 0xa0;
		if(uLen > 0x80){
			temp = uLen - 0x80;
			len = 0;
			for(i=0; i<temp; i++){
				factor = fgetc(file);
				len = len * 256 + factor;
			}
		}
		if(this->turn_num == 67){
			fseek(file, len, SEEK_CUR);
		}else {
			TlvMatching();
		}
	}
	if(fillFlag){
		fillInfos(this->turn_num);
	}
	return Len(len, endLen);
}

void CeParser::fillBits(int length){
	int num;
	char next;
	char temp[10];
	unsigned char uNext;
	strcpy(this->state, "");
	for(int i=0; i<length; i++){
		uNext = fgetc(file);
		num = uNext;
		sprintf(temp, "%02x", num);
		strcat(this->state, temp);
	}
}

// Accept the turn number to record different messages
void CeParser::fillInfos(int turn){
	// Write info messages into certificate parser
	switch(turn){
		case 4:
			strcpy(this->CA_Certificate.certificate.version.src1, "Version:   ");
			if(strcmp(this->state, "0") == 0)  strcpy(this->state, "v1");
			else if(strcmp(this->state, "1") == 0)  strcpy(this->state, "v2");
			else strcpy(this->state, "v3");
			strcpy(this->CA_Certificate.certificate.version.src2, this->state);
			break;
		case 5:
			strcpy(this->CA_Certificate.certificate.serialNum.src1, "Serial Number:   ");
			strcpy(this->CA_Certificate.certificate.serialNum.src2, this->state);
		case 7:
			strcpy(this->CA_Certificate.certificate.Algorithm.algorithm.src1, "Signature Alogorithm Name:   ");
			for(int i=0; i<8; i++){
				if(strcmp(this->state, this->SA[i].arr1) == 0){
					strcpy(this->CA_Certificate.certificate.Algorithm.algorithm.src2, SA[i].arr2);
					break;
				}
			}
			break;
		case 8:
			strcpy(this->CA_Certificate.certificate.Algorithm.parameters.src1, "The Signature Parameters:   ");
			strcpy(this->CA_Certificate.certificate.Algorithm.parameters.src2, this->state);
			break;
		case 12:
		case 16:
		case 20:
		case 24:
		case 28:
		case 32:
			for(int i=0; i<6; i++){
				if(strcmp(this->state, this->IS[i].arr1) == 0){
					strcpy(this->CA_Certificate.certificate.Issues[i].arr1, IS[i].arr2);
					strcat(this->CA_Certificate.certificate.Issues[i].arr1, "Of Issuer: \t");
					turn_temp = i;
					break;
				}
			}
			break;
		case 13:
		case 17:
		case 21:
		case 25:
		case 29:
		case 33:
			strcpy(this->CA_Certificate.certificate.Issues[turn_temp].arr2, this->state);
			break;
		case 35:
			strcpy(this->CA_Certificate.certificate.validation[0].src1, "The Begin Of Validity:    ");
			strcpy(this->CA_Certificate.certificate.validation[0].src2, this->state);
			break;
		case 36:
			strcpy(this->CA_Certificate.certificate.validation[1].src1, "The End Of Validity:    ");
			strcpy(this->CA_Certificate.certificate.validation[1].src2, this->state);
			break;
		case 40:
		case 44:
		case 48:
		case 52:
		case 56:
		case 60:
			for(int i=0; i<6; i++){
				if(strcmp(this->state, IS[i].arr1) == 0){
					strcpy(this->CA_Certificate.certificate.Subjects[i].arr1, IS[i].arr2);
					strcat(this->CA_Certificate.certificate.Subjects[i].arr1, "Of Subject: \t");
					this->turn_temp = i;
					break;
				}
			}
			break;
		case 41:
		case 45:
		case 49:
		case 53:
		case 57:
		case 61:
			strcpy(this->CA_Certificate.certificate.Subjects[turn_temp].arr2, this->state);
			break;
		case 64:
			strcpy(this->CA_Certificate.certificate.PublicKey.algorithm.src1, "Name Of Subject PublicKey's Algorithm:   ");
			for(int i=0; i<8; i++){
				if(strcmp(this->state, SA[i].arr1) == 0){
					strcpy(this->CA_Certificate.certificate.PublicKey.algorithm.src2, SA[i].arr2);
					break;
				}
			}
			break;
		case 65:
			strcpy(this->CA_Certificate.certificate.PublicKey.parameters.src1, "Parameters Of Subject PublicKey's Algorithm:   ");
			strcpy(this->CA_Certificate.certificate.PublicKey.parameters.src2, this->state);
			break;
		case 66:
			strcpy(this->CA_Certificate.certificate.PublicKey.publicKey.src1, "Subject PublicKey:   ");
			strcpy(this->CA_Certificate.certificate.PublicKey.publicKey.src2, this->state);
			break;
		case 69:
			strcpy(this->CA_Certificate.CAS_Algorithm.algorithm.src1, "Name Of Signature Algorithm:   ");
			for(int i=0; i<8; i++){
				if(strcmp(this->state, SA[i].arr1) == 0){
					strcpy(this->CA_Certificate.CAS_Algorithm.algorithm.src2, SA[i].arr2);
					break;
				}
			}
			break;
		case 70:
			strcpy(this->CA_Certificate.CAS_Algorithm.parameters.src1, "Parameters of Signature Algorithm:   ");
			strcpy(this->CA_Certificate.CAS_Algorithm.parameters.src2, this->state);
			break;
		case 71:
			strcpy(this->CA_Certificate.CAS_Value.value.src1, "Value of Signature:   ");
			strcpy(this->CA_Certificate.CAS_Value.value.src2, this->state);
			this->match_end = true;
	}
}

void CeParser::writeResult(char* path){
	ofstream out(path);
	if(out.is_open()){
		out << "X.509 Certificate: " << this->inputName << " Parse Result：\n\n";
		out << this->CA_Certificate.certificate.version.src1 << this->CA_Certificate.certificate.version.src2 << "\n";
		out << this->CA_Certificate.certificate.serialNum.src1 << this->CA_Certificate.certificate.serialNum.src2  << "\n";
		out << this->CA_Certificate.certificate.Algorithm.algorithm.src1 << this->CA_Certificate.certificate.Algorithm.algorithm.src2 << "\n";
		out << this->CA_Certificate.certificate.Algorithm.parameters.src1 << this->CA_Certificate.certificate.Algorithm.parameters.src2 << "\n";
		out << "Issuers:\n" << this->CA_Certificate.certificate.Issues[0].arr1 << this->CA_Certificate.certificate.Issues[0].arr2  << "\n";
		out << this->CA_Certificate.certificate.Issues[1].arr1 << this->CA_Certificate.certificate.Issues[1].arr2  << "\n" << this->CA_Certificate.certificate.Issues[2].arr1 << this->CA_Certificate.certificate.Issues[2].arr2  << "\n";
		out << this->CA_Certificate.certificate.Issues[3].arr1 << this->CA_Certificate.certificate.Issues[3].arr2  << "\n" << this->CA_Certificate.certificate.Issues[4].arr1 << this->CA_Certificate.certificate.Issues[4].arr2  << "\n";
		out << this->CA_Certificate.certificate.Issues[5].arr1 << this->CA_Certificate.certificate.Issues[5].arr2  << "\n";
		out << "Validity:\n" << this->CA_Certificate.certificate.validation[0].src2 << this->CA_Certificate.certificate.validation[1].src2 << "\n";
		out << "Subjects:\n" << this->CA_Certificate.certificate.Subjects[0].arr1 << this->CA_Certificate.certificate.Subjects[0].arr2  << "\n";
		out << this->CA_Certificate.certificate.Subjects[1].arr1 << this->CA_Certificate.certificate.Subjects[1].arr2  << "\n" << this->CA_Certificate.certificate.Subjects[2].arr1 << this->CA_Certificate.certificate.Subjects[2].arr2  << "\n";
		out << this->CA_Certificate.certificate.Subjects[3].arr1 << this->CA_Certificate.certificate.Subjects[3].arr2  << "\n" << this->CA_Certificate.certificate.Subjects[4].arr1 << this->CA_Certificate.certificate.Subjects[4].arr2  << "\n";
		out << this->CA_Certificate.certificate.Subjects[5].arr1 << this->CA_Certificate.certificate.Subjects[5].arr2  << "\n";
		out << this->CA_Certificate.certificate.PublicKey.algorithm.src1 << this->CA_Certificate.certificate.PublicKey.algorithm.src2 << "\n";
		out << this->CA_Certificate.certificate.PublicKey.parameters.src1 << this->CA_Certificate.certificate.PublicKey.parameters.src2 << "\n";
		out << this->CA_Certificate.certificate.PublicKey.publicKey.src1 << this->CA_Certificate.certificate.PublicKey.publicKey.src2 << "\n";
		out << "IssuerUniqueID:   None\n" << "SubjectUniqueID:   None\n" << "Extension:   None\n";
		out << this->CA_Certificate.CAS_Algorithm.algorithm.src1 << this->CA_Certificate.CAS_Algorithm.algorithm.src2 << "\n";
		out << this->CA_Certificate.CAS_Algorithm.parameters.src1 << this->CA_Certificate.CAS_Algorithm.parameters.src2 << "\n";
		out << this->CA_Certificate.CAS_Value.value.src1 << this->CA_Certificate.CAS_Value.value.src2 << "\n";
		out.close();
	}
	// Output result to termial
	ifstream in(path);
	cout << in.rdbuf();
	in.close();
}