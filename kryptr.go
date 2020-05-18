package main

import (
	"fmt"
	"io/ioutil"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/twistingmercury/color"
	"github.com/twistingmercury/kryptr/kryptomotron"
)

var (
	initFlag = flag.BoolP("init", "i", false, "Generate a new security key.")
	encFlag  = flag.StringP("action", "a", "", "Instructs kryptr on what to do with the input.  Acceptable values are  'encrypt' or 'decrypt'.")
	outFlag  = flag.StringP("out", "o", "", "The name of the output file to create.")
	recFlag  = flag.StringP("rpwd", "r", "", "Allows the passing in of a password to recover files that were ecrypted with an older security key.")

	// Version is the current version of the application.
	Version string = "v0.0.0"
	// Date is the date that this version was built.
	Date string = "who knows?"
)

func main() {
	flag.Parse()

	checkForVer()
	initialize()
	actOnFile()
}

func actOnFile() {
	info, err := os.Stdin.Stat()
	checkForErr(err)

	if info.Mode()&os.ModeCharDevice != 0 {
		fmt.Println("You have to pipe in a file.")
		return
	}

	in, err := ioutil.ReadAll(os.Stdin)
	checkForErr(err)

	switch *encFlag {
	case "encrypt":
		err = kryptomotron.Encrypt(in, *outFlag)
	case "decrypt":
		err = kryptomotron.Decrypt(in, *outFlag)
	case "":
		fmt.Println("the action flag was not provided.")
		flag.Usage()
		return
	default:
		fmt.Println("Invalid action flag:", *encFlag)
		flag.Usage()
		return
	}
	checkForErr(err)
}

func initialize() {
	if *initFlag {
		red := color.New(color.FgRed, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)

		red.Println(warning)
		fmt.Print("\nUnless you have the recovery password saved somewhere else, all currently encrypted files will be unrecoverable!\nAre you sure you want to do this? (YES | no)> ")
		var r string
		_, err := fmt.Scanln(&r)
		checkForErr(err)

		if r != "YES" {
			fmt.Println("Backing away slowly...")
			os.Exit(0)
		}

		rpwd, err := kryptomotron.NewKeys()
		checkForErr(err)

		fmt.Print("\nYour recovery password for the new security key is: ")
		yellow.Println(rpwd)
		fmt.Printf("Save this recovery password somewhere safe!  If you loose this password and run kryptr -i again, you will not be able to recover previously encrypted files!\n")
		os.Exit(0)
	}
}

func checkForVer() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		color.Cyan(kryptr)
		println(" - Version:    ", Version)
		println(" - Build Date: ", Date)
		os.Exit(0)
	}
}

func checkForErr(err error) {
	if err != nil {
		println(err.Error())
		flag.Usage()
		os.Exit(1)
	}
}
