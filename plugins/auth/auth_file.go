package main

import (
	"fmt"
	"io/ioutil"
)

type Handler struct{}

func (Handler) GetSecretKey(accessKey string) (string, error) {
	b, err := ioutil.ReadFile("/root/sk")
	if err != nil {
        return "", err
	}

	return fmt.Sprintf("%s", string(b)), nil
}

func GetAuthHandler() (f interface{}, err error) {
    f = Handler{}
    return
}
