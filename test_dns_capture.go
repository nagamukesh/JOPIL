// +build ignore

package main

import (
	"encoding/binary"
	"fmt"

	"github.com/mukesh/jopil/internal/parser"
)

// Mock DNS query packet for example.com (A record)
// DNS header: ID=1, QR=0 (query), QDCOUNT=1
// Question: example.com, type=A (1), class=IN (1)
func createMockDNSQuery() []byte {
	payload := make([]byte, 29)

	// DNS Header (12 bytes)
	binary.BigEndian.PutUint16(payload[0:2], 1)     // ID = 1
	binary.BigEndian.PutUint16(payload[2:4], 0)     // Flags: query, not response
	binary.BigEndian.PutUint16(payload[4:6], 1)     // QDCOUNT = 1 question
	binary.BigEndian.PutUint16(payload[6:8], 0)     // ANCOUNT = 0
	binary.BigEndian.PutUint16(payload[8:10], 0)    // NSCOUNT = 0
	binary.BigEndian.PutUint16(payload[10:12], 0)   // ARCOUNT = 0

	// Question: example.com (length-prefixed labels)
	offset := 12
	labels := []string{"example", "com"}
	for _, label := range labels {
		payload[offset] = byte(len(label))
		offset++
		copy(payload[offset:], label)
		offset += len(label)
	}
	payload[offset] = 0 // Root label
	offset++

	// QTYPE = A (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2

	// QCLASS = IN (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)

	return payload
}

// Mock DNS response packet
func createMockDNSResponse() []byte {
	payload := make([]byte, 45)

	// DNS Header (12 bytes)
	binary.BigEndian.PutUint16(payload[0:2], 1)     // ID = 1
	binary.BigEndian.PutUint16(payload[2:4], 0x8000) // Flags: response, no error
	binary.BigEndian.PutUint16(payload[4:6], 1)     // QDCOUNT = 1
	binary.BigEndian.PutUint16(payload[6:8], 1)     // ANCOUNT = 1
	binary.BigEndian.PutUint16(payload[8:10], 0)    // NSCOUNT = 0
	binary.BigEndian.PutUint16(payload[10:12], 0)   // ARCOUNT = 0

	// Question: example.com
	offset := 12
	labels := []string{"example", "com"}
	for _, label := range labels {
		payload[offset] = byte(len(label))
		offset++
		copy(payload[offset:], label)
		offset += len(label)
	}
	payload[offset] = 0 // Root label
	offset++

	// QTYPE = A (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2

	// QCLASS = IN (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2

	// Answer RR: example.com -> 93.184.216.34
	// Name (pointer to offset 12)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 0xc00c)
	offset += 2

	// TYPE = A (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2

	// CLASS = IN (1)
	binary.BigEndian.PutUint16(payload[offset:offset+2], 1)
	offset += 2

	// TTL = 3600
	binary.BigEndian.PutUint32(payload[offset:offset+4], 3600)
	offset += 4

	// RDLENGTH = 4
	binary.BigEndian.PutUint16(payload[offset:offset+2], 4)
	offset += 2

	// RDATA = 93.184.216.34
	payload[offset] = 93
	payload[offset+1] = 184
	payload[offset+2] = 216
	payload[offset+3] = 34

	return payload[:offset+4]
}

func main() {
	fmt.Println("=== DNS Capture Test ===\n")

	// Test 1: Parse DNS query
	fmt.Println("Test 1: Parse DNS Query")
	queryPayload := createMockDNSQuery()
	fmt.Printf("Query payload size: %d bytes\n", len(queryPayload))

	queryResp := parser.ParseDNS(queryPayload)
	if queryResp == nil {
		fmt.Println("❌ FAILED: ParseDNS returned nil for valid query")
		return
	}

	if queryResp.IsResponse {
		fmt.Println("❌ FAILED: Query marked as response")
		return
	}

	if len(queryResp.Questions) != 1 {
		fmt.Printf("❌ FAILED: Expected 1 question, got %d\n", len(queryResp.Questions))
		return
	}

	q := queryResp.Questions[0]
	if q.Name != "example.com" {
		fmt.Printf("❌ FAILED: Expected 'example.com', got '%s'\n", q.Name)
		return
	}

	if q.Type != 1 {
		fmt.Printf("❌ FAILED: Expected type 1 (A), got %d\n", q.Type)
		return
	}

	fmt.Printf("✓ Query parsed correctly - Domain: %s, Type: %s\n\n", q.Name, parser.GetQueryType(q.Type))

	// Test 2: Parse DNS response
	fmt.Println("Test 2: Parse DNS Response")
	respPayload := createMockDNSResponse()
	fmt.Printf("Response payload size: %d bytes\n", len(respPayload))

	respResp := parser.ParseDNS(respPayload)
	if respResp == nil {
		fmt.Println("❌ FAILED: ParseDNS returned nil for valid response")
		return
	}

	if !respResp.IsResponse {
		fmt.Println("❌ FAILED: Response not marked as response")
		return
	}

	if len(respResp.Questions) != 1 {
		fmt.Printf("❌ FAILED: Expected 1 question in response, got %d\n", len(respResp.Questions))
		return
	}

	q = respResp.Questions[0]
	if q.Name != "example.com" {
		fmt.Printf("❌ FAILED: Expected 'example.com', got '%s'\n", q.Name)
		return
	}

	fmt.Printf("✓ Response parsed correctly - Domain: %s, Response Code: %s\n\n", q.Name, parser.GetResponseCode(respResp.ResponseCode))

	fmt.Println("=== All DNS capture tests passed! ===")
}
