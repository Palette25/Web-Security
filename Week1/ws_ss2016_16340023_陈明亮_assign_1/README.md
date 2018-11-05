# README for DES-Design

## 文件目录结构：
	ws_ss2016_16340023_陈明亮_assign_1
	│ 
	├── bin
	│   ├─ main.exe
	│
	├── pkg
	│	├─ windows_amd64
	│		├─ Des.a
	│
	├── src
	│   ├─ Des
	│	│	├─ Des.go
	│	│
	│   ├─ main.go
	│	
	├── testData
	│   ├─ cipher.txt
	│	├─ key.txt
	│	├─ plain.txt
	│
	├── Homework1.pdf

## 测试可执行文件方法：
1. 进入bin文件夹，打开终端，注意到测试文本输入不在bin文件夹内，而是在上一级目录的testData中。

2. 终端执行以下命令：
```
./main.exe ../testData/plain.txt ../testData/key.txt ../testData/cipher.txt
```

3. 查看打印的加密密文，以及解密结果，验证程序可行性。