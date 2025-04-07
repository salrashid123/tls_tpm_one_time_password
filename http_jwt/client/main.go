package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	label = "EXPORTER-Channel-Binding"
)

var (
	rootca = flag.String("rootca", "certs/root-ca.crt", "RootCA File")
	keyID  = flag.String("keyID", "client_1", "Client id")
	key    = flag.String("key", "my_api_key", "API KEY")
)

func main() {

	flag.Parse()

	caCert, err := os.ReadFile(*rootca)
	if err != nil {
		fmt.Printf("Error reading cacert %v\n", err)
		return
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ServerName:       "server.domain.com",
		RootCAs:          serverCertPool,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},
	}

	conn, err := tls.Dial("tcp", "localhost:8081", tlsConfig)
	if err != nil {
		fmt.Printf("Error dialing %v\n", err)
		return
	}
	cs := conn.ConnectionState()

	ekmSign, err := cs.ExportKeyingMaterial(label, []byte("sig_key"), 32)
	if err != nil {
		fmt.Printf("Error getting ekm %v\n", err)
		return
	}

	ekmEncrypt, err := cs.ExportKeyingMaterial(label, []byte("enc_key"), 32)
	if err != nil {
		fmt.Printf("Error getting ekm %v\n", err)
		return
	}

	// Start standard HMAC
	macS := hmac.New(sha256.New, []byte(*key))
	macS.Write(ekmSign)
	derivedSigningKey := macS.Sum(nil)

	macE := hmac.New(sha256.New, []byte(*key))
	macE.Write(ekmEncrypt)
	derivedEncryptionKey := macE.Sum(nil)

	// End standard HMAC

	fmt.Printf("derived SigningKey: %s\n", base64.StdEncoding.EncodeToString(derivedSigningKey))
	fmt.Printf("derived EncryptionKey: %s\n", base64.StdEncoding.EncodeToString(derivedEncryptionKey))

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := http.Client{
		Transport: tr,
	}

	// now encrypt signedAccessToken
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: derivedEncryptionKey, KeyID: *keyID}, (&jose.EncrypterOptions{}).WithContentType("JWT").WithType("JWT"))
	if err != nil {
		fmt.Printf("Error reading creating tempAccessToken %v\n", err)
		return
	}

	//signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: derivedSigningKey}, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("client"), *keyID))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: derivedSigningKey}, nil)
	if err != nil {
		fmt.Printf("Error reading creating tempAccessToken %v\n", err)
		return
	}

	cl := jwt.Claims{
		Subject: "subject",
		Issuer:  "issuer",
	}

	// sign only
	// serialized, err := jwt.Signed(signer).Claims(cl).Serialize()
	// if err != nil {
	// 	fmt.Printf("encrypting and signing JWT: %s\n", err)
	// 	return
	// }
	// end sign only

	// sign and encrypt
	serialized, err := jwt.SignedAndEncrypted(signer, enc).Claims(cl).Serialize()
	if err != nil {
		fmt.Printf("encrypting and signing JWT: %s\n", err)
		return
	}

	fmt.Printf("Encrypted JWE: %s\n", serialized)
	// end sign and encrypt

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8081/get", nil)
	if err != nil {
		fmt.Printf("Error creating request %v\n", err)
		return
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", serialized))
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request %v\n", err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error response %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf("%s\n", string(htmlData))

}
