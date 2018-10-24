/*
*  DES Algorithm with golang in OOP structure
*  PARAMETERS:
*  	1. source File Path -- The target plain text for des processing
*	2. secret key file Path -- The text file storing des crypt secret key
*	3. [output File Path] -- The destination file path for output, if not exist then just print in terminal
*/

package Des

import (
	"fmt"
	"os"
)

var (
	// IP, IP_Reverse, PC_1, PC_2 arrays
	IP = [64]int{
	 	58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
	 	62, 54, 46, 38, 30, 22, 14, 6,
	 	64, 56, 48, 40, 32, 24, 16, 8,
	 	57, 49, 41, 33, 25, 17, 9,  1,
	 	59, 51, 43, 35, 27, 19, 11, 3,
	 	61, 53, 45, 37, 29, 21, 13, 5,
	 	63, 55, 47, 39, 31, 23, 15, 7}
	IP_Reverse = [64]int{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25}
	PC_1 = [56]int{
		57, 49, 41, 33, 25, 17, 9,
	   	1, 58, 50, 42, 34, 26, 18,
	  	10,  2, 59, 51, 43, 35, 27,
	  	19, 11,  3, 60, 52, 44, 36,
	  	63, 55, 47, 39, 31, 23, 15,
	   	7, 62, 54, 46, 38, 30, 22,
	  	14,  6, 61, 53, 45, 37, 29,
	  	21, 13,  5, 28, 20, 12,  4}
	PC_2 = [48]int{
		14, 17, 11, 24,  1,  5,
	    3, 28, 15,  6, 21, 10,
	   23, 19, 12,  4, 26,  8,
	   16,  7, 27, 20, 13,  2,
	   41, 52, 31, 37, 47, 55,
	   30, 40, 51, 45, 33, 48,
	   44, 49, 39, 56, 34, 53,
	   46, 42, 50, 36, 29, 32}
	// Left Shift Bits array
	ShiftBits = [16]int{
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}
	// Extension table and P-Box, S-Box
	Ex_Table = [48]int{
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1}
	P_Box = [32]int{
		16, 7, 20, 21, 29, 12, 28, 17, 
		1,  15, 23, 26, 5,  18, 31, 10,
		2,  8, 24, 14, 32, 27, 3,  9,  
		19, 13, 30, 6,  22, 11, 4, 25}
	S_Box = [8][4][16]int{
		/*S1*/
		{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
		{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
		{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
		{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
		/*S2*/
		{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
		{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
		{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
		{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
		/*S3*/
		{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
		{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
		{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
		{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
		/*S4*/
		{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
		{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
		{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
		{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
		/*S5*/
		{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
		{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
		{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
		{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
		/*S6*/
		{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
		{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
		{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
		{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
		/*S7*/
		{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
		{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
		{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
		{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
		/*S8*/
		{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
		{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
		{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
		{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}}
)

/*
*  Golang-class DES-Processor definition
*/
type DES_Processor struct{
	message string;  // Input plain text
	secretBytes string;  // Init secret string
	plainText [64]int;  // Plain text array
	secretKey [64]int;  // Secret-Key
	subKeys [16][48]int;  // 16 turns subKeys
	cipherText [64]int;  // Cipher text array
	cipherResult string;  // Final cipher result text
	originLen int;
};

// Startup of the whole des processing, 0 for encode, 1 for decode
func (d *DES_Processor) DES_Perform(inFile string, secretKeyFile string, outFile string, type_ bool){
	// 1. Open Target File
	file, err := os.Open(inFile);
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Opening Error: %s does not exist!\n", inFile);
		os.Exit(2);
	}
	defer file.Close();
	// Load file size
	fileInfo, err := file.Stat();
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Status Error: %s has error status!\n", inFile);
		os.Exit(2);
	}
	fileSize := fileInfo.Size();
	buffer := make([]byte, fileSize);
	// Read Input File
	file.Read(buffer);

	// 2. Checking secret file
	sfile, err := os.Open(secretKeyFile);
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Opening Error: %s does not exist\n", secretKeyFile);
		os.Exit(2);
	}
	defer sfile.Close();
	// Load secret key content
	sfileInfo, err := sfile.Stat();
	if err != nil {
		fmt.Fprintf(os.Stderr, "File Status Error: %s has error status!\n", secretKeyFile);
		os.Exit(2);
	}
	sfileSize := sfileInfo.Size();
	buff := make([]byte, sfileSize);
	sfile.Read(buff);
	d.secretBytes = string(buff);

	// Start DES Algorithm Steps
	if type_ == false {
		// Encrypt
		d.message = string(buffer);
		d.EncryptText();
	} else {
		// Decrypt
		d.cipherResult = string(buffer);
		d.DecryptText();
	}

	// 3. Checking whether dest File exist or not (ReWrite / Create)
	if outFile != "" {
		var (
			isExist = true
			outfile *os.File
			outerr error
			res string
		)
		if _, err := os.Stat(outFile); os.IsNotExist(err) {
			isExist = false;
		}

		if isExist {
			fmt.Printf("File %s exists, will rewrite its content....\n", outFile);
			outfile, outerr = os.OpenFile(outFile, os.O_WRONLY, 0777);
		} else {
			fmt.Printf("File %s does not exist, will create it....\n", outFile);
			outfile, outerr = os.Create(outFile);
		}
		defer outfile.Close();
		if type_ == false {
			res = d.cipherResult;
		} else {
			res = d.message;
		}
		// Also print in the terminal
		fmt.Printf("Final Result: %s\n", res);
		// Data writing
		_, outerr = outfile.WriteString(res);
		if outerr != nil {
			fmt.Fprintf(os.Stderr, "File Writing Error: Cannot write result into \"%s\"!\n", outFile);
			os.Exit(2);
		}
	}
}
// Encrypt the input text file
func (d *DES_Processor) EncryptText(){
	var (
		process [64]int
		length = len(d.message)/8;
	)
	d.originLen = len(d.message);
	d.StringToBits();
	d.generateSubKeys();
	d.PCKSAdding();
	for i:=0; i<length; i++ {
		d.generateSource(i*8, false);
		d.IP_Permutation(&process, false);
		d.T_Iteration(process, &d.cipherText, false);
		d.IP_Reverse_Permutation(false);
	}
}

// Decrypt the input text file
func (d *DES_Processor) DecryptText(){
	var (
		process [64]int
		length = len(d.cipherResult)/8;
	)
	d.StringToBits();
	d.generateSubKeys();
	for i:=0; i<length; i++ {
		d.generateSource(i*8, true);
		d.IP_Permutation(&process, true);
		d.T_Iteration(process, &d.plainText, true);
		d.IP_Reverse_Permutation(true);
	}
	// Delete PCKS5 Adding
	d.message = string(d.message[:d.originLen]);
}

// First Step of class DES-Process --- IP Permutate
func (d *DES_Processor) IP_Permutation(request *[64]int, type_ bool){
	if type_ == false {
		// Type 0: Encrypting
		for i:=0; i<64; i++ {
			(*request)[63-i] = d.plainText[64-IP[i]];
		}
	} else {
		// Type 1: Decrypting
		for i:=0; i<64; i++ {
			(*request)[63-i] = d.cipherText[64-IP[i]];
		}
	}
}

// Second Step of class DES-Process --- T Iteration
func (d *DES_Processor) T_Iteration(process [64]int, target *[64]int, type_ bool){
	var (
		leftP [32]int
		rightP [32]int
	)
	// Initialize L1 And R1
	for i:=0; i<32; i++ {
		leftP[i] = process[i+32];
		rightP[i] = process[i];
	}
	// 16 T-Iteration
	for round:=0; round<16; round++ {
		var index int = round;
		if type_ == true{
			index = 15-round;
		}
		tmp := rightP;
		FeistelRes := Feistel(rightP, d.subKeys[index]);
		for i:=0; i<32; i++ {
			rightP[i] = leftP[i] ^ FeistelRes[i];  // XOR
		}
		leftP = tmp;
	}
	// Combine L16, R16 into R16L16
	for i:=0; i<32; i++ {
		(*target)[i] = leftP[i];
		(*target)[i+32] = rightP[i];
	}
}

// Last Step of class DES-Process --- IP Reverse Permutation
func (d *DES_Processor) IP_Reverse_Permutation(type_ bool){
	var (
		tmp [64]int
		byteArr [8]byte
	)
	if type_ == false {
		tmp = d.cipherText;
		for i:=0; i<64; i++ {
			d.cipherText[63-i] = tmp[64-IP_Reverse[i]];
		}
		for i:=0; i<64; i++ {
			byteArr[i/8] += byteArr[i/8] + byte(d.cipherText[i]);
		}
		d.cipherResult += string(byteArr[:]);
	} else {
		tmp = d.plainText;
		for i:=0; i<64; i++ {
			d.plainText[63-i] = tmp[64-IP_Reverse[i]];
		}
		for i:=0; i<64; i++ {
			byteArr[i/8] += byteArr[i/8] + byte(d.plainText[i]);
		}
		d.message += string(byteArr[:]);
	}
}

// Transform string to bit array
func (d *DES_Processor) StringToBits(){
	// Plain or cryptMess, Secret Keys Transform
	for i:=0; i<8; i++ {
		currFix := d.secretBytes[i];
		for j:=0; j<8; j++ {
			d.secretKey[i*8+(7-j)] = int(currFix % 2);
			currFix >>= 1;
		}
	}
}

// Gnerate source int array from input
func (d *DES_Processor) generateSource(srcIndex int, type_ bool){
	var messFix byte;
	for i:=0; i<8; i++ {
		if type_ == false {
			messFix = d.message[i+srcIndex];
		} else {
			messFix = d.cipherResult[i+srcIndex];
		}
		for j:=0; j<8; j++ {
			if type_ ==  false {
				d.plainText[i*8+(7-j)] = int(messFix % 2);
			} else {
				d.cipherText[i*8+(7-j)] = int(messFix % 2);
			}
			messFix >>= 1;
		}
	}
}

// PCKS#5 Adding
func (d *DES_Processor) PCKSAdding(){
	count := 8 - (len(d.message) % 8);
	for i:=0; i<count; i++ {
		d.message += string(count);
	}
}

// Generate 16 subkeys from input secret key
func (d *DES_Processor) generateSubKeys(){
	var (
		realKey [56]int
		leftKey [28]int
		rightKey [28]int
		result [48]int
	)
	// Drop eight parity bits
	for i:=0; i<56; i++ {
		realKey[55-i] = d.secretKey[64 - PC_1[i]];
	}
	// Sixteen times subKey generating
	for time:=0; time<16; time++ {
		// Divide 56 bits key into two parts
		for i:=0; i<28; i++ {
			leftKey[i] = realKey[i+28];
			rightKey[i] = realKey[i];
		}
		Left_Shift_bits(&leftKey, time);
		Left_Shift_bits(&rightKey, time);
		// Comnination and Compression
		for i:=0; i<28; i++ {
			realKey[i+28] = leftKey[i];
			realKey[i] = rightKey[i]; 
		}
		for i:=0; i<48; i++ {
			result[47-i] = realKey[56 - PC_2[i]];
		}
		// One Round SubKey generate finish
		d.subKeys[time] = result;
	}
}

/*
*  Tools functions definition
*/
// Feistel function
func Feistel(input_R [32]int, input_k [48]int) (result_ [32]int) {
	var (
		result [32]int
		expand_R [48]int
		count int = 0
	)
	for i:=0; i<48; i++ {
		expand_R[47-i] = input_R[32-Ex_Table[i]];
	}
	for i:=0; i<48; i++ {
		expand_R[i] = expand_R[i] ^ input_k[i];
	}
	// S_Box Transform
	for i:=0; i<48; i+=6 {
		row := expand_R[47-i] * 2 + expand_R[47-i-5];
		col := expand_R[47-i-1] * 8 + expand_R[47-i-2] * 4 + expand_R[47-i-3] * 2 + expand_R[47-i-4];
		for index, target := 0, S_Box[i/6][row][col]; index <= 3; index++ {
			var tmp int = target % 2;
			result[31-count-index] = tmp;
			target = target / 2;
		}
		count += 4;
	}
	// P-Permutation
	var temp [32]int = result;
	for i:=0; i<32; i++ {
		result[31-i] = temp[32-P_Box[i]];
	}
	return result;
}

func Left_Shift_bits(input *[28]int, time int){
	var (
		shiftNum = ShiftBits[time]
		temp [28]int
	)
	for i:=0; i<28; i++ {
		temp[i] = input[i];
	}
	for i:=27; i>=0; i-- {
		if i-shiftNum < 0 {
			(*input)[i] = temp[i-shiftNum+28];
		} else {
			(*input)[i] = temp[i-shiftNum];
		}
	}
}
