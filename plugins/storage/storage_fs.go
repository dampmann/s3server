package main

import (
	"io/ioutil"
)

type Handler struct{}

func (Handler) StoreObject(name string, body []byte) error {
	err := ioutil.WriteFile("/root/"+name, body, 0644)
	if err != nil {
        return err
	}

    return nil
}

func GetStorageHandler() (f interface{}, err error) {
    f = Handler{}
    return
}
