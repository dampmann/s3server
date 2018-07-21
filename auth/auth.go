package auth

type CredentialsHandler interface {
    GetSecretKey(accessKey string) (string, error)
}

