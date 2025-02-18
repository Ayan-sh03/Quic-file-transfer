package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestGenerateTLSConfig(t *testing.T) {
	tlsConfig := generateTLSConfig()

	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	if len(tlsConfig.Certificates) == 0 {
		t.Error("No certificates found in TLS config")
	}

	if tlsConfig.NextProtos[0] != "quic-file-transfer" {
		t.Errorf("Expected next proto 'quic-file-transfer', got '%s'", tlsConfig.NextProtos[0])
	}
}

func TestFileTransfer(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test-files")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Start the server in a goroutine
	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()
		main() // Run the server's main function
	}()

	// Wait for a short time to allow the server to start
	time.Sleep(1 * time.Second)

	// Create a QUIC configuration for the client
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-file-transfer"},
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout: time.Second * 5,
	}

	// Create a QUIC connection to the server
	conn, err := quic.DialAddr(context.Background(), "localhost:8080", tlsConf, quicConfig)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Create a test file and its content
	testFilename := "test_file.txt"
	testFileContent := "This is the content of the test file."

	// Open a stream
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send the filename
	filenameLen := len(testFilename)
	if filenameLen > 255 {
		t.Fatalf("Filename too long")
	}
	_, err = stream.Write([]byte{byte(filenameLen)})
	if err != nil {
		t.Fatalf("Failed to write filename length: %v", err)
	}
	_, err = stream.Write([]byte(testFilename))
	if err != nil {
		t.Fatalf("Failed to write filename: %v", err)
	}

	// Send the file content
	_, err = io.Copy(stream, bytes.NewBufferString(testFileContent))
	if err != nil {
		t.Fatalf("Failed to write file content: %v", err)
	}

	// Close the stream
	err = stream.Close()
	if err != nil {
		t.Fatalf("Failed to close stream: %v", err)
	}

	// Wait for the file creation signal
	var createdFile string
	select {
	case filePath := <-fileCreatedChan:
		createdFile = filePath
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for file creation signal")
	}

	// Check if the file was created
	//var createdFile string
	//err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
	//	if err != nil {
	//		return err
	//	}
	//	if !info.IsDir() && strings.HasPrefix(info.Name(), testFilename) {
	//		createdFile = path
	//		return io.EOF // Stop walking
	//	}
	//	return nil
	//})
	//
	//if err != nil && err != io.EOF {
	//	t.Fatalf("Error walking directory: %v", err)
	//}

	//if createdFile == "" {
	//	t.Fatalf("File was not created")
	//}
	createdFile = filepath.Join(tempDir, createdFile)

	// Read the content of the created file
	createdFileContent, err := os.ReadFile(createdFile)
	if err != nil {
		t.Fatalf("Failed to read created file: %v", err)
	}

	// Check if the content is correct
	if string(createdFileContent) != testFileContent {
		t.Errorf("File content does not match. Expected: %q, got: %q", testFileContent, string(createdFileContent))
	}

	serverWg.Wait() // Wait for the server to finish (in case you signal it to stop)
}
