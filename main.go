package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var fileCreationMutex sync.Mutex

func main() {
	// Generate TLS config
	tlsConfig := generateTLSConfig()

	// Start QUIC server
	listener, err := quic.ListenAddr(":8080", tlsConfig, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Server listening on :8080")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}

		go func() {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				log.Println("Failed to accept stream:", err)
				return
			}

			// Read filename length first (as a single byte)
			filenameLenBuf := make([]byte, 1)
			_, err = stream.Read(filenameLenBuf)
			if err != nil {
				log.Println("Failed to read filename length:", err)
				return
			}
			filenameLen := int(filenameLenBuf[0])

			// Read filename with exact length
			filename := make([]byte, filenameLen)
			_, err = io.ReadFull(stream, filename)
			if err != nil {
				log.Println("Failed to read filename:", err)
				return
			}

			// Lock the file creation process
			fileCreationMutex.Lock()
			defer fileCreationMutex.Unlock()

			// Create the file
			timestamp := time.Now().Format("20060102150405")
			file, err := os.Create(string(filename) + "_" + timestamp + ".txt")
			if err != nil {
				log.Println("Failed to create file:", err)
				return
			}
			defer file.Close()

			// Copy the remaining data (actual file content) to the file
			fmt.Println("Receiving file:", string(filename))
			_, err = io.Copy(file, stream)
			if err != nil {
				log.Println("Failed to receive file:", err)
				return
			}

			fmt.Println("File received successfully!")
		}()
	}
}

// Generate a basic self-signed certificate
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-file-transfer"},
	}
}
