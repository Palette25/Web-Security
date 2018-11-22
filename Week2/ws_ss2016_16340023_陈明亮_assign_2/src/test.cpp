#include "md5.h"
#include <ctime>

int main(){
	cout << "Begin MD5_Processor Speed Test...\nTest size: 50000 * 20000 KB\nTest data type: .jpg\nTest start..." << endl;
	string path;
	MD5_Processor mp("../testData/sky.jpg");
	int time = 50000;
	clock_t start = clock(), finish;
	while(time-- > 0){
		mp.MD5_Init();
		unsigned char* plain = mp.getPlainText();

		mp.MD5_Update(plain, mp.getLength());
		mp.MD5_Final(false);
	}
	finish = clock();
	double dur = (double)(finish - start) / CLOCKS_PER_SEC;
	cout << "Test end...\nDuration time: " << dur << " seconds" << endl;

	return 0;
}