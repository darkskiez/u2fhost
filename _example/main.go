package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/darkskiez/u2fhost"
)

func main() {
	ctx := context.Background()
	app := u2fhost.NewClient("http://foobar.com")

	fmt.Println("Commands: (r)egister / (a)uthenticate / (c)heck / (q)uit")
	reader := bufio.NewReader(os.Stdin)

	khs := make([]u2fhost.KeyHandler, 0)

	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			log.Fatal("Unable to read command stdin")
		}

		switch char {
		case 'c':
			fmt.Println("Checking inserted tokens")
			resp, err := app.CheckAuthenticate(ctx, khs)
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
			resp, err := app.Register(ctx)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				khs = append(khs, resp.SignedKeyHandle())
				fmt.Printf("Added Token %v\n", len(khs))
			}

		case 'a':
			fmt.Println("Touch or Insert Token to authenticate")
			aresp, err := app.Authenticate(ctx, khs)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				fmt.Printf("Authenticated Token %d\n", aresp.KeyHandleIndex)
			}
		case 'q':
			return
		}
	}
}
