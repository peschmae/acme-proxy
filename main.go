package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/peschmae/acmepipe/pkg/acme"
)

func main() {
	r := chi.NewRouter()

	// logger := httplog.NewLogger("acme-logger", httplog.Options{
	// 	JSON:             true,
	// 	LogLevel:         slog.LevelDebug,
	// 	Concise:          true,
	// 	RequestHeaders:   true,
	// 	MessageFieldName: "message",
	// 	// TimeFieldFormat: time.RFC850,
	// 	Tags: map[string]string{
	// 		"version": "v1.0-81aa4244d9fc8076a",
	// 		"env":     "dev",
	// 	},
	// 	QuietDownRoutes: []string{
	// 		"/acme/directory",
	// 	},
	// 	QuietDownPeriod: 10 * time.Second,
	// })

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	//r.Use(httplog.RequestLogger(logger))
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	r.Mount("/acme", acme.Router())

	generateCertificates()
	server := http.Server{
		Addr:    ":3000",
		Handler: r,
	}
	server.ListenAndServeTLS("cert.pem", "key.pem")
}

// Source: https://stackoverflow.com/a/10510783/446681
func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func generateCertificates() {
	certFile := "cert.pem"
	privateKeyFile := "key.pem"

	if fileExists(certFile) && fileExists(privateKeyFile) {
		return
	}

	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	subject := pkix.Name{
		Organization:       []string{"Hector"},
		OrganizationalUnit: []string{"testing"},
		CommonName:         "Hector was here",
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Generate a private key. This is equivalent to running:
	// 		openssl genrsa -out key.pem 2048
	keyOut, _ := os.Create(privateKeyFile)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()
	log.Printf("Generated file key.pem (your private key)")

	// Generate a self-signed certificate that contains your public key.
	// This is what a certificate authority (like https://letsencrypt.org/)
	// would do for you. Notice that it embeds your public key on it.
	//
	// This is equivalent to generating a certificate with:
	//		openssl req -new -x509 -key key.pem -out cert.pem -days 365
	//
	// You can decode the contents of this certificate on your machine by
	// running:
	//		openssl x509 -in cert.pem -text -noout
	//
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("Generated file cert.pem with public key:")
	// log.Printf("%#v", pk.PublicKey)
	log.Printf("%x\r\n\r\n", pk.PublicKey.N)
}
