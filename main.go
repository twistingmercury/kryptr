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

	keyflag  = flag.Bool("setup-keys", false, "Generate a new security key.")
	encflag  = flag.Bool("encrypt", false, "Encrypt the specified file.")
	decflag  = flag.Bool("decrypt", false, "Decrypt the specified file.")
	outflag  = flag.StringP("out", "o", "", "The name of the output file to create.")
	inflag   = flag.StringP("in", "i", "", "The name of the file to be acted upon.")
	delflag  = flag.BoolP("del-in-file", "d", true, "Deletes the original file that was encrypted.")
	helpflag = flag.BoolP("help", "h", false, "Displays help information.")
	recflag  = flag.String("password", "", "Allows the passing in of a password to recover files that were ecrypted with an older security key.")
)

var (
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
)

const encodeStd = "0123456789+!@#$%^&*+?:|ABCDEHMNPQRSTUVWXYZacdeifklmnopqrstuvwxyz"

func main() {
	flag.Parse()
	checkHelp()
	checkVer()
	setup()
	in, out := strings.TrimSpace(*inflag), strings.TrimSpace(*outflag)

	rpwd := *recflag
	if len(rpwd) > 0 {
		checkErr(kryptomotron.Recover(in, out, rpwd))
	} else {
		checkErr(kryptomotron.Kryptomogrify(in, out, *encflag, *decflag))
	}

	if *delflag && *encflag {
		checkErr(os.Remove(in))
	}
}

func checkHelp() {
	if *helpflag || len(os.Args) == 1 {
		ver()
		flag.Usage()
		os.Exit(0)
	}
}

func help() {
	flag.Usage()
}

func setup() {
	if !*keyflag {
		return
	}

	red.Println(warning)
	fmt.Print("\nUnless you have the recovery password saved somewhere else, all currently encrypted files will be unrecoverable!\nAre you sure you want to do this? (YES | no)> ")
	var r string
	i, err := fmt.Scanln(&r)

	if err != nil && i > 0 {
		println(err.Error())
	}

	if r != "YES" {
		fmt.Println("Backing away slowly...")
		os.Exit(0)
	}

	pwd, err := kryptomotron.NewKeys()
	checkErr(err)

	fmt.Print("\nYour recovery password for the new security key is: ")
	yellow.Println(pwd)
	fmt.Printf("Save this recovery password somewhere safe!  If you loose this password and run kryptr --setup-keys again you will not be able to recover previously encrypted files!\n")
	os.Exit(0)
}

func checkVer() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		ver()
		os.Exit(0)
	}
}

func ver() {
	color.Cyan(kryptr)
	println(" - Version:    ", Version)
	println(" - Build Date: ", Date)
}

func checkErr(err error) {
	if err == nil {
		return
	}
	red.Println("Error:", err.Error())
	help()
	os.Exit(1)
}
