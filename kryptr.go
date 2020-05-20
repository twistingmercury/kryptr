package main

import (
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/twistingmercury/color"
	"github.com/twistingmercury/kryptr/kryptomotron"
)

var (
	// Version is the current version of the application.
	Version string = "v0.0.0"
	// Date is the date that this version was built.
	Date string = "who knows?"

	keyflag = flag.BoolP("key-setup", "k", false, "Generate a new security key.")
	encflag = flag.Bool("encrypt", false, "Encrypt the specified file.")
	decflag = flag.Bool("decrypt", false, "Decrypt the specified file.")
	outflag = flag.StringP("out", "o", "", "The name of the output file to create.")
	//recflag  = flag.StringP("rpwd", "r", "", "Allows the passing in of a password to recover files that were ecrypted with an older security key.")
	inflag   = flag.StringP("target", "i", "", "The name of the file to be acted upon.")
	delflag  = flag.BoolP("del-in-file", "d", true, "Deletes the original file that was encrypted.")
	helpflag = flag.BoolP("help", "h", false, "Displays help information.")
)

func main() {
	flag.Parse()
	help()
	checkVer()
	setup()
	in, out := strings.TrimSpace(*inflag), strings.TrimSpace(*outflag)
	checkErr(kryptomotron.Kryptomogrefy(in, out, *encflag, *decflag))
}

func help() {
	if *helpflag {
		flag.Usage()
		os.Exit(0)
	}
}

func setup() {
	if !*keyflag {
		return
	}

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	red.Println(warning)
	fmt.Print("\nUnless you have the recovery password saved somewhere else, all currently encrypted files will be unrecoverable!\nAre you sure you want to do this? (YES | no)> ")
	var r string
	_, err := fmt.Scanln(&r)
	checkErr(err)

	if r != "YES" {
		fmt.Println("Backing away slowly...")
		os.Exit(0)
	}

	rpwd, err := kryptomotron.NewKeys()
	checkErr(err)

	fmt.Print("\nYour recovery password for the new security key is: ")
	yellow.Println(rpwd)
	fmt.Printf("Save this recovery password somewhere safe!  If you loose this password and run kryptr -i again, you will not be able to recover previously encrypted files!\n")
	os.Exit(0)
}

func checkVer() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		color.Cyan(kryptr)
		println(" - Version:    ", Version)
		println(" - Build Date: ", Date)
		os.Exit(0)
	}
}

func checkErr(err error) {
	if err != nil {
		println(err.Error())
		println("kryptr -a=encrypt -i=some/file/path -o=output/file/path")
		flag.Usage()
		os.Exit(1)
	}
}
