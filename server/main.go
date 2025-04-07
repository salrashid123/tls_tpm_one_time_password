package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"

	//"net/http/httputil"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "certs/tpm-key.pem", "privateKey File")
	pskID   = flag.String("pskID", "mypsk-id", "PSK")
	key     = flag.String("key", "my_api_key", "API KEY")
)

const ()

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	ekm        []byte
	derivedKey []byte
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		c := r.Header.Get("client")
		if c == "" {
			http.Error(w, "Error: no clientid provided in header", http.StatusInternalServerError)
			return
		}
		fmt.Printf("deriving API key for client: %s\n", c)

		ekm, err := r.TLS.ExportKeyingMaterial("EXPORTER-my_label", []byte(c), 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Start standard HMAC
		mac := hmac.New(sha256.New, []byte(*key))
		mac.Write(ekm)
		derivedKey := mac.Sum(nil)
		// End standard HMAC

		// start TPM HMAC
		// derivedKey, err := common.TPMHMAC(*tpmPath, *in, ekm)
		// if err != nil {
		// 	http.Error(w, "Error calculating hmac %v\n", http.StatusInternalServerError)
		// 	return
		// }
		// end TPM HMAC

		fmt.Printf("derived APIKey: %s\n", base64.StdEncoding.EncodeToString(ekm))

		e := r.Header.Get("apikey")
		if e == "" {
			http.Error(w, "Error: no ekm provided in header", http.StatusInternalServerError)
			return
		}

		if base64.StdEncoding.EncodeToString(derivedKey) != e {
			http.Error(w, "Error: no ekm provided in header", http.StatusInternalServerError)
			return
		}

		event := &event{
			ekm:        ekm,
			derivedKey: derivedKey,
		}

		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	//val := r.Context().Value(contextKey("event")).(event)
	//fmt.Printf("EKM %v\n", base64.StdEncoding.EncodeToString(val.ekm))
	fmt.Fprint(w, "ok")
}

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

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/get").HandlerFunc(gethandler)

	var err error
	tlsConfig := &tls.Config{
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},
	}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("certs/server.crt", "certs/server.key")
	fmt.Printf("Unable to start Server %v", err)

}
