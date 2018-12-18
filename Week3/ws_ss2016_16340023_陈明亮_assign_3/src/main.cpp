#include "X509_Ce_Parser.h"

int main(int argc, char* argv[]){
	char path[100] = {'\0'};
	if(argc < 2){
		cout << "Please enter the certificate's path: ";
		cin >> path;
	}else {
		for(int i=0; i<strlen(argv[1]); i++){
			path[i] = argv[1][i];
		}
	}
	cout << path << endl;
	// Check path vlidation
	ifstream in(path, ios::in | ios::binary);
	if(!in.is_open()){
		cout << "[Error] Please enter a valid file path!" << endl;
		return -1;
	}
	// Start Parsing
	cout << "Start Certificate Parsing...." << endl;
	CeParser cp(path);
	cp.startParsing();
	cout << "End Certificate Parsing...." << endl;
	return 0;
}