package parser

import (
	"encoding/binary"
)

// DNSQuestion represents a DNS query question
type DNSQuestion struct {
	Name  string // Domain name
	Type  uint16 // Query type (A, AAAA, MX, CNAME, etc.)
	Class uint16 // Query class (usually 1 for IN)
}

// DNSResponse represents a DNS response
type DNSResponse struct {
	Questions []DNSQuestion
	ResponseCode uint8 // RCODE field (0=NoError, 1=FormErr, 2=ServFail, 3=NXDomain, etc.)
	IsResponse bool   // True if this is a response packet
}

// ParseDNS parses a DNS packet and extracts queries/responses
// Returns nil if packet is not valid DNS
func ParseDNS(payload []byte) *DNSResponse {
	if len(payload) < 12 {
		return nil
	}

	// Check DNS header
	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := (flags & 0x8000) != 0
	
	// Extract question count
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount == 0 {
		return nil
	}

	// Extract response code (only relevant for responses)
	rcode := uint8(flags & 0x0F)

	// Parse questions
	offset := 12
	questions := make([]DNSQuestion, 0, qdcount)

	for i := 0; i < int(qdcount); i++ {
		// Parse domain name
		name, newOffset := parseDomainName(payload, offset)
		if newOffset == -1 || newOffset+4 > len(payload) {
			return nil // Invalid DNS packet
		}

		qtype := binary.BigEndian.Uint16(payload[newOffset : newOffset+2])
		qclass := binary.BigEndian.Uint16(payload[newOffset+2 : newOffset+4])

		questions = append(questions, DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})

		offset = newOffset + 4
	}

	return &DNSResponse{
		Questions:    questions,
		ResponseCode: rcode,
		IsResponse:   isResponse,
	}
}

// parseDomainName parses a DNS domain name starting at offset
// Returns the domain name and the offset after the name
// Returns ("", -1) if parsing fails
func parseDomainName(payload []byte, offset int) (string, int) {
	var labels []string
	
	for offset < len(payload) {
		length := payload[offset]
		offset++

		// Pointer (compression) - not fully handling for simplicity
		if length&0xC0 == 0xC0 {
			// Compression pointer - skip it (pointer is 2 bytes total)
			if offset >= len(payload) {
				return "", -1
			}
			break // End of this label (pointer indicates end)
		}

		// Root label (end of name)
		if length == 0 {
			break
		}

		// Regular label
		if offset+int(length) > len(payload) {
			return "", -1
		}

		labels = append(labels, string(payload[offset:offset+int(length)]))
		offset += int(length)
	}

	// Join labels with dots
	domain := ""
	for i, label := range labels {
		if i > 0 {
			domain += "."
		}
		domain += label
	}

	return domain, offset
}

// GetQueryType returns a human-readable name for DNS query type
func GetQueryType(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return "?"
	}
}

// GetResponseCode returns a human-readable DNS response code
func GetResponseCode(rcode uint8) string {
	switch rcode {
	case 0:
		return "NoError"
	case 1:
		return "FormErr"
	case 2:
		return "ServFail"
	case 3:
		return "NXDomain"
	case 4:
		return "NotImpl"
	case 5:
		return "Refused"
	default:
		return "?"
	}
}
