
## TPM One Time Password using TLS SessionKey

This repo demonstrates an authentication flow where a the bearer token sent between the client and server is unique to the TLS session used.

In other words, each `client->server` TLS connetion will derive a unique, non-resuable bearer token on both the client and server.   The server will only
accept application layer data if the bearer tokens match.

This conecept is similar to [HOTP: An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/rfc4226/)  except that in place of the "counter" to HMAC, the [TLS Exported Key Material (EKM)](https://datatracker.ietf.org/doc/html/rfc5705) is used.

One major advanatage of this flow is that even if the derivedKey is exfiltrated, it is useless since it can only be used on that specific TLS session.

In this flow, both the client and server needs to have an initial shared secret.  This can be an HMAC key loaded into the client's `Trusted Platform Module(TPM)` which helps ensure the security of the shared key.

![images/TLS_TPM_OTP.png](images/TLS_TPM_OTP.png)

As shown:

1. client loads the shared hmac key
2. client connects to server over TLS
3. client extracts the EKM
4. client derives the sessionKey though calling KDF with HMAC(EKM)
5. client sends the sessionKey and its own client identifier to the server
6. server derives the EKM
7. sever extracts the client_identifer
8. server acquires the deriveKey using KDF with hmac(client_identifier, EKM)
9. if derivedKeys match, proceed.


Also see:

- [Per-Session TLS1.2-PSK using Trusted Platform Module (TPM)](https://github.com/salrashid123/tls_psk_tpm)
- [Exported Key Material (EKM) in golang and openssl](https://github.com/salrashid123/go_ekm_tls)
- [Hybrid Public Key Encryption (HPKE) with per-message TPM-based PSK Authentication](https://github.com/salrashid123/hpke_tpm_psk)

### Setup


The default demo here will use a `software tpm` ([swtpm](https://github.com/stefanberger/swtpm)) and HMAC keys already embedded into the client-side TPM.

To run, just start the server and client. Only the client will use a TPM to derive the key and note that the derivedKey is unique to each connection


```bash
$ go run server/main.go 
Starting Server..
    deriving API key for client: client1
    derived APIKey: ntbOfmI/pojI+/SgzQDTL8xdpGwuQho4qnerCoqNwQY=

    deriving API key for client: client1
    derived APIKey: AVMdDD8EpdkM+oEmjf/6Pz8A9ARe/wXEHNShR1XR8Ic=
```

```bash
## start the softwareTPM witht the configuration in this repo.
swtpm socket \
  --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

$ go run client/main.go 
    derived APIKey: ntbOfmI/pojI+/SgzQDTL8xdpGwuQho4qnerCoqNwQY=
    200 OK
    ok

$ go run client/main.go 
    derived APIKey: AVMdDD8EpdkM+oEmjf/6Pz8A9ARe/wXEHNShR1XR8Ic=
    200 OK
    ok
```

Note that since the samples uses `go1.24`, you can use a key-exchange suite that is quantum resistent by setting the following flag:

```bash
export GODEBUG=tlsmlkem=1
$ go version
   go version go1.24.0 linux/amd64
```
For more information see, [X25519MLKEM768 client server in go](https://github.com/salrashid123/ml-kem-tls-keyexchange)


### Using JWE and JWS

This repo also contains a sample where instead of just a header, the derivedKey is used to encrypt and or sign a JSON structure.

See the example in the `http_jwt_*/` folder.   The default example shows a signed JWT using the derivedKey.

- `signed`

```bash
## start the softwareTPM
swtpm socket \
  --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

$ go run http_jwt_server/main.go 
    Starting Server..
    derived SigningKey: XwZghLVmPF/U5I+9yK1ZwxJNptLP6Se74Y1CSMQfJTY=

$ go run http_jwt_client/main.go 
    derived SigningKey: XwZghLVmPF/U5I+9yK1ZwxJNptLP6Se74Y1CSMQfJTY=
    Signed: eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.fLSIRp4So0H2Pe9HAyqAgprpE7m5Mdb3JEvkM6SOPhc
    200 OK
    ok
```

where the jwt header is

```json
{
  "alg": "HS256"
}
```

- `encrypted then signed`

```bash
$ go run http_jwt_server/main.go 
    Starting Server..
    derived SigningKey: jq4CJ/H08l+m/dfJi96a1OHeId80ZtZvz8xiJpuW+i8=
    derived EncryptionKey: E1NrJbfb/n4DJvXvngemQLBya4HdO+DkHLblV3cGYFE=


$ go run http_jwt_client/main.go 
    derived SigningKey: jq4CJ/H08l+m/dfJi96a1OHeId80ZtZvz8xiJpuW+i8=
    derived EncryptionKey: E1NrJbfb/n4DJvXvngemQLBya4HdO+DkHLblV3cGYFE=
    Encrypted JWE: eyJhbGciOiJkaXIiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiY2xpZW50XzEiLCJ0eXAiOiJKV1QifQ..UufNES78x_xBEyb1.SU3IvwAJdRP868vdiWvQTuWomnv-1lSpQn0VvIDkp3bQhTIRgGNIHs3AmeKiGPM6NkHaYa0l_d3KvY766Tk-Tc5BjkZ2akliC8qbOxvkZqU3pAS9f99vy0XZe4PfvvF_tHaxUcijTFSXScaR.I0drMfegG3lkwV19eD7USw
    200 OK
    ok
```

where the JWE header is:

```json
{
  "alg": "dir",
  "cty": "JWT",
  "enc": "A256GCM",
  "kid": "client_1",
  "typ": "JWT"
}
```

### Using TPM

If you wanted the client to initialize a new swtpm and your own hmac key (vs the defualt swtpm in this library which uses `my_api_key` as root key), the following will create a software TPM and load/import an HMAC key.

```bash
sudo swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

export secret="my_api_key"
echo -n $secret > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2 import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx
tpm2_encodeobject -C primary.ctx -u hmac.pub -r hmac.priv -o tpm-key.pem
```


