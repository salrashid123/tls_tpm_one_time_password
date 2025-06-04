package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	tpmkdf "github.com/salrashid123/tpm-kdf/hmac"
)

const (
	label = "EXPORTER-Channel-Binding"
)

var (
	rootca  = flag.String("rootca", "certs/root-ca.crt", "RootCA File")
	keyID   = flag.String("keyID", "client_1", "Client id")
	key     = flag.String("key", "my_api_key", "API KEY")
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "certs/tpm-key.pem", "privateKey File")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

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
	// smac := hmac.New(sha256.New, []byte(*key))
	// smac.Write(ekmSign)
	// derivedSigningKey := smac.Sum(nil)

	// emac := hmac.New(sha256.New, []byte(*key))
	// emac.Write(ekmEncrypt)
	// derivedEncryptionKey := emac.Sum(nil)
	// End standard HMAC

	// start TPM KDF since hmac is PRF
	// B) start TPM
	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("Error reading file %v\n", err)
		return
	}

	// B1) derive key using TPM hmac
	derivedSigningKey, err := tpmkdf.TPMHMAC(*tpmPath, nil, c, nil, nil, "", ekmSign)
	if err != nil {
		fmt.Printf("Error getting TPMHMAC %v\n", err)
		return
	}

	derivedEncryptionKey, err := tpmkdf.TPMHMAC(*tpmPath, nil, c, nil, nil, "", ekmEncrypt)
	if err != nil {
		fmt.Printf("Error getting TPMHMAC %v\n", err)
		return
	}
	// end TPM HMAC

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
