#include "md5.h"
#include <ctime>

int main(){
	string path;
	cout << "Please enter file path: ";
	cin >> path;
	MD5_Processor mp(path);
	mp.MD5_Init();
	unsigned char* plain = mp.getPlainText();

	mp.MD5_Update(plain, mp.getLength());
	mp.MD5_Final(true);

	return 0;
}