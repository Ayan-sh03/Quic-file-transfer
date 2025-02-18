package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	defer conn.Close()

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

	// Give the server some time to create the file
	time.Sleep(2 * time.Second)

	// Construct the expected file path
	var createdFile string
	err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasPrefix(info.Name(), testFilename) {
			createdFile = path
			return io.EOF // Stop walking
		}
		return nil
	})

	if err != nil && err != io.EOF {
		t.Fatalf("Error walking directory: %v", err)
	}

	if createdFile == "" {
		t.Fatalf("File was not created")
	}

	// Read the content of the created file
	createdFileContent, err := os.ReadFile(createdFile)
	if err != nil {
		t.Fatalf("Failed to read created file: %v", err)
	}

	// Check if the content is correct
	if string(createdFileContent) != testFileContent {
		t.Errorf("File content does not match. Expected: %q, got: %q", testFileContent, string(createdFileContent))
	}

	// Clean up the created file
	err = os.Remove(createdFile)
	if err != nil {
		t.Fatalf("Failed to remove created file: %v", err)
	}
}

func TestMultipleFileTransfers(t *testing.T) {
	numClients := 5
	var wg sync.WaitGroup
	wg.Add(numClients)

	testFilename := "test_file.txt"

	for i := 0; i < numClients; i++ {
		fileContent := fmt.Sprintf("This is the content of file %d", i)
		go func(clientNum int, content string) {
			defer wg.Done()

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
				t.Errorf("Client %d: Failed to dial: %v", clientNum, err)
				return
			}
			defer conn.Close()

			// Open a stream
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				t.Errorf("Client %d: Failed to open stream: %v", clientNum, err)
				return
			}
			defer stream.Close()

			// Send the filename
			filenameLen := len(testFilename)
			if filenameLen > 255 {
				t.Errorf("Client %d: Filename too long", clientNum)
				return
			}
			_, err = stream.Write([]byte{byte(filenameLen)})
			if err != nil {
				t.Errorf("Client %d: Failed to write filename length: %v", clientNum, err)
				return
			}
			_, err = stream.Write([]byte(testFilename))
			if err != nil {
				t.Errorf("Client %d: Failed to write filename: %v", clientNum, err)
				return
			}

			// Send the file content
			_, err = io.Copy(stream, bytes.NewBufferString(content))
			if err != nil {
				t.Errorf("Client %d: Failed to write file content: %v", clientNum, err)
				return
			}

			// Close the stream
			err = stream.Close()
			if err != nil {
				t.Errorf("Client %d: Failed to close stream: %v", clientNum, err)
				return
			}
		}(i, fileContent)
	}

	wg.Wait()

	// Give the server some time to create the files
	time.Sleep(5 * time.Second)

	// Verify that all files were created
	for i := 0; i < numClients; i++ {
		expectedContent := fmt.Sprintf("This is the content of file %d", i)
		var createdFile string
		err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasPrefix(info.Name(), testFilename) && strings.Contains(info.Name(), fmt.Sprintf("_%d", i)) {
				createdFile = path
				return io.EOF // Stop walking
			}
			return nil
		})

		if err != nil && err != io.EOF {
			t.Errorf("Error walking directory: %v", err)
			continue
		}

		if createdFile == "" {
			t.Errorf("File for client %d was not created", i)
			continue
		}

		// Read the content of the created file
		createdFileContent, err := os.ReadFile(createdFile)
		if err != nil {
			t.Errorf("Client %d: Failed to read created file: %v", i, err)
			continue
		}

		// Check if the content is correct
		if string(createdFileContent) != expectedContent {
			t.Errorf("Client %d: File content does not match. Expected: %q, got: %q", i, expectedContent, string(createdFileContent))
		}

		// Clean up the created file
		err = os.Remove(createdFile)
		if err != nil {
			t.Errorf("Client %d: Failed to remove created file: %v", i, err)
		}
	}
}
