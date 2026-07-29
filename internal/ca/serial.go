package ca

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// SerialSource allocates certificate serial numbers.
type SerialSource interface {
	Next() (*big.Int, error)
}

// RandomSerialSource generates serial numbers as 20 random bytes (160
// bits), with the top bit cleared to keep the DER INTEGER encoding
// non-negative per RFC 5280 §4.1.2.2. It requires no persisted state and is
// safe for concurrent use.
type RandomSerialSource struct{}

func (RandomSerialSource) Next() (*big.Int, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}
	buf[0] &^= 0x80 // clear the top bit so the INTEGER stays non-negative
	return new(big.Int).SetBytes(buf), nil
}
