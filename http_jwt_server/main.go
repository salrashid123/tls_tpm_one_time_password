package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/sdk/helper/kdf"
	"golang.org/x/net/http2"
)

var (
	key = flag.String("key", "my_api_key", "API KEY")
)

const (
	label = "EXPORTER-Channel-Binding"
)

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	client string
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get(string("Authorization"))
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusInternalServerError)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Authorization header value not found", http.StatusInternalServerError)
			return
		}

		raw := parts[1]

		// start sign only
		// tok, err := jwt.ParseSigned(raw,
		// 	[]jose.SignatureAlgorithm{jose.HS256})
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }
		// end sign only

		// start to encrypt then sign
		tok, err := jwt.ParseSignedAndEncrypted(raw,
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A256GCM},
			[]jose.SignatureAlgorithm{jose.HS256})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// end encrypt then sign

		ekmSign, err := r.TLS.ExportKeyingMaterial(label, []byte("sig_key"), 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// start to encrypt then sign
		ekmEncrypt, err := r.TLS.ExportKeyingMaterial(label, []byte("enc_key"), 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// end encrypt then sign

		// Start standard HMAC

		prf := kdf.HMACSHA256PRF
		prfLen := kdf.HMACSHA256PRFLen

		/// Vault
		derivedSigningKey, err := kdf.CounterMode(prf, prfLen, []byte(*key), ekmSign, 256)
		if err != nil {
			fmt.Printf("Error getting ekm %v\n", err)
			return
		}

		derivedEncryptionKey, err := kdf.CounterMode(prf, prfLen, []byte(*key), ekmEncrypt, 256)
		if err != nil {
			fmt.Printf("Error getting ekm %v\n", err)
			return
		}

		// end encrypt then sign

		// End standard HMAC

		fmt.Printf("derived SigningKey: %s\n", base64.StdEncoding.EncodeToString(derivedSigningKey))
		fmt.Printf("derived EncryptionKey: %s\n", base64.StdEncoding.EncodeToString(derivedEncryptionKey))

		// start to encrypt then sign
		t, err := tok.Decrypt(derivedEncryptionKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// end encrypt then sign

		nested := &jwt.Claims{}
		// start sign only
		//tok.Claims(derivedSigningKey, nested)
		// end sign only

		// start sign and encrypt
		t.Claims(derivedSigningKey)
		err = t.Claims(derivedSigningKey, nested)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// end sign and encrypt

		event := &event{
			client: nested.Subject,
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
