package main

// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// single chunk
// next multiple chunks
import (
	"fmt"
	"github.com/dampmann/s3server/util"
	"github.com/dampmann/s3server/auth"
	"github.com/dampmann/s3server/storage"
    "flag"
	"log"
	"net/http"
    "plugin"
)

func RequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
        parsedRequest, err := util.NewParsedRequest(r)
        if err != nil {
            http.Error(w, err.Msg, err.Code)
            return
        }

		err = util.VerifyRequestSignature(parsedRequest, authservice)
		if err != nil {
            http.Error(w, err.Msg, err.Code)
            return
		}
	} else {
		fmt.Println("*** else ***")
	}
	w.Write([]byte(""))
}

var authplugin = flag.String("authplugin", "plugins/auth/auth_file.so", "The plugin to load user credentials")
var storageplugin = flag.String("storageplugin", "plugins/storage/storage_fs.so", "The plugin to use to store data")
var authservice auth.CredentialsHandler
var storageservice storage.StorageHandler

func main() {
    flag.Parse()
	authp, err := plugin.Open(*authplugin)
	if err != nil {
        log.Fatal(err)
	}

    GetAuthHandler, err := authp.Lookup("GetAuthHandler")
    if err != nil {
        log.Fatal(err)
    }
    authiface, err := GetAuthHandler.(func() (interface{}, error))()
    authservice = authiface.(auth.CredentialsHandler)

	storagep, err := plugin.Open(*storageplugin)
	if err != nil {
        log.Fatal(err)
	}

    GetStorageHandler, err := storagep.Lookup("GetStorageHandler")
    if err != nil {
        log.Fatal(err)
    }
    storageiface, err := GetStorageHandler.(func() (interface{}, error))()
    storageservice = storageiface.(storage.StorageHandler)


	http.HandleFunc("/", RequestHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
