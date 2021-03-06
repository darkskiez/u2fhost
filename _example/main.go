package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"

	"github.com/darkskiez/u2fhost"
)

func main() {
	ctx := context.Background()
	app := u2fhost.NewClient("http://foobar.com")
	app.ErrorHandler = func(err error) { log.Print(err) }
	fmt.Println("Commands: (r)egister / (a)uthenticate / (c)heck / (q)uit")
	reader := bufio.NewReader(os.Stdin)

	khs := []u2fhost.KeyHandler{}
	pks := []*ecdsa.PublicKey{}

	clientdata := "{If talking to a remote server put info like hostname here}"

	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			log.Fatal("Unable to read command stdin")
		}

		switch char {
		case 'c':
			fmt.Println("Checking inserted tokens")
			resp, err := app.CheckAuthenticate(ctx, clientdata, khs)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				if resp {
					fmt.Println("Recognised Token Inserted")
				} else {
					fmt.Println("No Recognised Token Inserted")
				}
			}
		case 'r':
			fmt.Println("Touch or Insert Token to register")
			resp, err := app.Register(ctx, clientdata)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				err = resp.CheckSignature()
				if err != nil {
					fmt.Printf("CheckSignature Failed (ignoring): %v\n", err)
				}
				khs = append(khs, resp.KeyHandle)
				pks = append(pks, resp.PublicKey)
				fmt.Printf("Added Token %v\n", len(khs))
			}

		case 'a':
			fmt.Println("Touch or Insert Token to authenticate")
			aresp, err := app.Authenticate(ctx, clientdata, khs)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				fmt.Printf("Authenticated Token %d\n", aresp.KeyHandleIndex+1)
				if err = aresp.CheckSignature(pks[aresp.KeyHandleIndex]); err != nil {
					fmt.Printf("CheckSignature Failed: %v\n", err)
					continue
				}
				fmt.Printf("Validated Token Signature\n")
			}
		case 'q':
			return
		}
	}
}
