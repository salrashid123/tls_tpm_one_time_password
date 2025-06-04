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

	// kbkdf "github.com/canonical/go-kbkdf"

	"github.com/hashicorp/vault/sdk/helper/kdf"
	tpmkdf "github.com/salrashid123/tpm-kdf/hmac"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
)

var (
	ekm      []byte
	tpmPath  = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in       = flag.String("in", "certs/tpm-key.pem", "privateKey File")
	rootca   = flag.String("rootca", "certs/root-ca.crt", "RootCA File")
	clientID = flag.String("clientID", "client1", "Client")
	key      = flag.String("key", "my_api_key", "API KEY")
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
	ekm, err = cs.ExportKeyingMaterial("EXPORTER-my_label", []byte(*clientID), 32)
	if err != nil {
		fmt.Printf("Error getting ekm %v\n", err)
		return
	}

	// A) Start standard HMAC to derive a key since its a PRF
	// mac := hmac.New(sha256.New, []byte(*key))
	// mac.Write(ekm)
	// derivedKey := mac.Sum(nil)
	// End standard HMAC

	// B) start TPM
	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("Error reading file %v\n", err)
		return
	}

	// B1) derive key using TPM hmac
	// derivedKey, err := tpmkdf.TPMHMAC(*tpmPath, nil, c, nil, nil, "", ekm)
	// if err != nil {
	// 	fmt.Printf("Error getting TPMHMAC %v\n", err)
	// 	return
	// }

	// B2) derive key using TPM-based KDF and vault's wrapper
	prfLen := kdf.HMACSHA256PRFLen
	derivedKey, err := kdf.CounterMode(func(key []byte, data []byte) ([]byte, error) {
		return tpmkdf.TPMHMAC(*tpmPath, nil, c, nil, nil, "", data)
	}, prfLen, nil, ekm, 256)
	if err != nil {
		fmt.Printf("Error getting TPMHMAC %v\n", err)
		return
	}

	// end TPM HMAC

	fmt.Printf("derived APIKey: %s\n", base64.StdEncoding.EncodeToString(derivedKey))

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := http.Client{
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8081/get", nil)
	if err != nil {
		fmt.Printf("Error creating request %v\n", err)
		return
	}
	// do something here with the ekm value...

	req.Header.Add("client", *clientID)
	req.Header.Add("apikey", base64.StdEncoding.EncodeToString(derivedKey))
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
