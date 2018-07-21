package storage

type StorageHandler interface {
    StoreObject(name string, body []byte) error
}

