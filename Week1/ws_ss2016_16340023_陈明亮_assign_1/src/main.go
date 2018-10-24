/*
*  Main go scipt for invoking and testing DES Processor
*/
package main

import (
	"./Des"
	"os"
	"fmt"
)

func main(){
	// Receive cli params
	var (
		args = os.Args[0:]
		outFilePath string
	)
	if len(args) < 3 {
		usage(args[0]);
		os.Exit(1);
	}
	// Normal creating des processor
	dester := new(Des.DES_Processor)
	if len(args) >= 3 {
		outFilePath = args[3];
	}else {
		outFilePath = "";
	}
	// Perform des encrypt
 	dester.DES_Perform(args[1], args[2], outFilePath, false);
 	// Decrypt
 	dester.DES_Perform(outFilePath, args[2], args[1], true);

}

func usage(progName string){
	fmt.Fprintf(os.Stderr, "USAGE: ./%s  srcFilePath secretFilePath [outFilePath] type\n", progName);
}
