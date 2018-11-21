#include "md5.h"

int main(){
	MD5_Processor mp("../testData/test.txt");

	mp.MD5_Init();
	unsigned char* plain = mp.getPlainText();
	mp.MD5_Update(plain, (int)(strlen((char*)plain)));
	mp.MD5_Final();

	return 0;
}