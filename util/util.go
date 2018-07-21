package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/dampmann/s3server/s3errors"
    "github.com/dampmann/s3server/auth"
    "github.com/dampmann/s3server/storage"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	algo              = "AWS4-HMAC-SHA256"
	timeFormat        = "20060102T150405Z"
	shortTimeFormat   = "20060102"
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

type ParsedRequest struct {
	Method        string
	Url           url.URL
	Algorithm     string
	Scope         string
	AccessKey     string
	SignedHeaders []string
	Signature     string
	Region        string
	ScopeDate     string
	Body          []byte
	RR            *http.Request
    AuthBackend auth.CredentialsHandler
    StorageBackend storage.StorageHandler
}

func NewParsedRequest(r *http.Request) (*ParsedRequest, *s3errors.S3Error) {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, algo) {
		return nil, &s3errors.S3Error{Code: 400,
			CodeString: "InvalidEncryptionAlgorithmError",
			Msg:        "The encryption request you specified is not valid. The valid value is AES256."}
	}

	authorization = strings.TrimPrefix(authorization, algo)
	authorization = strings.Replace(authorization, " ", "", -1)
	if strings.Index(authorization, "Credential=") == -1 {
		return nil, &s3errors.S3Error{Code: 403,
			CodeString: "InvalidSecurity",
			Msg:        "The provided security credentials are not valid."}
	}

	if strings.Index(authorization, "SignedHeaders=") == -1 {
		return nil, &s3errors.S3Error{Code: 403,
			CodeString: "InvalidSecurity",
			Msg:        "The provided security credentials are not valid."}
	}

	if strings.Index(authorization, "Signature=") == -1 {
		return nil, &s3errors.S3Error{Code: 403,
			CodeString: "InvalidSecurity",
			Msg:        "The provided security credentials are not valid."}
	}

	pr := &ParsedRequest{}
	pr.Body = make([]byte, 0)
	pr.RR = r
	pr.Method = r.Method
	pr.Algorithm = algo
	fields := strings.Split(authorization, ",")

	if len(fields) == 0 {
		return nil, &s3errors.S3Error{Code: 403,
			CodeString: "InvalidSecurity",
			Msg:        "The provided security credentials are not valid."}
	}

	for i := 0; i < len(fields); i++ {
		if strings.HasPrefix(fields[i], "Credential=") {
			fields[i] = strings.Replace(fields[i], "Credential=", "", -1)
			pr.Scope = fields[i]
			creds := strings.Split(pr.Scope, "/")
			if len(creds) == 5 {
				pr.AccessKey = creds[0]
				pr.ScopeDate = creds[1]
				pr.Region = creds[2]
			} else {
				return nil, &s3errors.S3Error{Code: 403,
					CodeString: "InvalidSecurity",
					Msg:        "The provided security credentials are not valid."}
			}
		}

		if strings.HasPrefix(fields[i], "SignedHeaders=") {
			fields[i] = strings.Replace(fields[i], "SignedHeaders=", "", -1)
			pr.SignedHeaders = strings.Split(fields[i], ";")
		}

		if strings.HasPrefix(fields[i], "Signature=") {
			fields[i] = strings.Replace(fields[i], "Signature=", "", -1)
			pr.Signature = fields[i]
		}
	}

	return pr, nil
}

func canonicalQuery(u url.URL) string {
	queryString := ""
	m := u.Query()
	var cm = make(map[string]string)
	for k := range m {
		cm[url.QueryEscape(k)] = url.QueryEscape(m[k][0])
	}

	keys := make([]string, 0, len(cm))
	for k := range cm {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for index, k := range keys {
		queryString += fmt.Sprintf("%s=%s", k, cm[k])
		if index != len(keys)-1 {
			queryString += "&"
		}
	}

	return queryString
}

func canonicalHeaders(pr *ParsedRequest) string {
	ch := ""
	sort.Strings(pr.SignedHeaders)
	for _, v := range pr.SignedHeaders {
		ch += fmt.Sprintf("%s:%s\n", strings.ToLower(v),
			strings.TrimSpace(pr.RR.Header.Get(v)))
	}

	return ch
}

func canonicalRequestURI(u url.URL) string {
	var requestURI string
	if len(u.Opaque) > 0 {
		requestURI = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		requestURI = u.EscapedPath()
	}

	if len(requestURI) == 0 {
		requestURI = "/"
	}

	return requestURI
}

func getHashedPayload(pr *ParsedRequest) string {
	// if the payload is large that will cause trouble
	//handle unsigned payload
	var err error
	pr.Body, err = ioutil.ReadAll(pr.RR.Body)
	if err != nil {
		fmt.Println("Error: %v", err)
		return ""
	}
	h := sha256.New()
	h.Write(pr.Body)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getHashedCanonicalRequest(req string) string {
	h := sha256.New()
	h.Write([]byte(req))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sign(rregion string, rdate string, stringToSign string, sk string) string {
	date := hmac.New(sha256.New, []byte("AWS4"+sk))
	date.Write([]byte(rdate))
	region := hmac.New(sha256.New, []byte(date.Sum(nil)))
	region.Write([]byte(rregion))
	service := hmac.New(sha256.New, []byte(region.Sum(nil)))
	service.Write([]byte("s3"))
	req := hmac.New(sha256.New, []byte(service.Sum(nil)))
	req.Write([]byte("aws4_request"))
	signature := hmac.New(sha256.New, []byte(req.Sum(nil)))
	signature.Write([]byte(stringToSign))
	return fmt.Sprintf("%x", signature.Sum(nil))
}

func VerifyRequestSignature(pr *ParsedRequest, as auth.CredentialsHandler) *s3errors.S3Error {
	hashedPayload := ""
	if pr.RR.ContentLength == 0 {
		hashedPayload = emptyStringSHA256
	} else {
		hashedPayload = getHashedPayload(pr)
	}

	pr.RR.Header.Add("Host", pr.RR.Host)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		pr.Method,
		canonicalRequestURI(*pr.RR.URL),
		canonicalQuery(*pr.RR.URL),
		canonicalHeaders(pr),
		strings.Join(pr.SignedHeaders, ";"),
		hashedPayload)
	//fmt.Fprintf(os.Stdout, "\n==\n%v\n==\n", canonicalRequest)
	hcr := getHashedCanonicalRequest(canonicalRequest)
	//fmt.Println(hcr)
	scope := strings.Split(pr.Scope, "/")
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algo,
		pr.RR.Header.Get("x-amz-date"),
		strings.Join(scope[1:], "/"),
		hcr)
	//fmt.Println(stringToSign)
    sk, err := as.GetSecretKey(pr.AccessKey)
    if err != nil {
		return &s3errors.S3Error{Code: 500,
			CodeString: "InternalServerError",
			Msg:        fmt.Sprintf("%s", err)}
    }
	signature := sign(pr.Region, pr.ScopeDate, stringToSign, sk)
	if signature != pr.Signature {
		return &s3errors.S3Error{Code: 403,
			CodeString: "SignatureDoesNotMatch",
			Msg:        "The request signature we calculated does not match the signature you provided. Check your AWS secret access key and signing method."}
	}
	fmt.Println("+++ authenticated ", signature, "+++")
	return nil
}
