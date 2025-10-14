package customercryptociphersuite

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// seqNumPlaceholder used only for CID builder path (RFC9146).
	seqNumPlaceholder = 0xffffffffffffffff
)

type ChaCha struct {
	localCipher  cipher.AEAD
	remoteCipher cipher.AEAD

	localWriteIV  []byte
	remoteWriteIV []byte
}

func NewChaCha(localKey, localIV, remoteKey, remoteIV []byte) (*ChaCha, error) {
	c := &ChaCha{
		localWriteIV:  localIV,
		remoteWriteIV: remoteIV,
	}

	var err error
	c.localCipher, err = chacha20poly1305.New(localKey)
	if err != nil {
		return nil, fmt.Errorf("create local cipher: %w", err)
	}
	c.remoteCipher, err = chacha20poly1305.New(remoteKey)
	if err != nil {
		return nil, fmt.Errorf("create remote cipher: %w", err)
	}
	return c, nil
}

func buildSeq64(epoch uint16, seq48 uint64) uint64 {
	return (uint64(epoch) << 48) | (seq48 & ((1 << 48) - 1))
}


func buildNonce(writeIV []byte, epoch uint16, seq48 uint64) []byte {
	var padded [12]byte
	// padded[0..3] == 0x00
	binary.BigEndian.PutUint64(padded[4:], buildSeq64(epoch, seq48))
	nonce := make([]byte, 12)
	for i := 0; i < 12; i++ {
		nonce[i] = writeIV[i] ^ padded[i]
	}
	return nonce
}

func (c *ChaCha) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]

	// compute nonce from epoch+sequence, XOR with localWriteIV
	nonce := buildNonce(c.localWriteIV, pkt.Header.Epoch, pkt.Header.SequenceNumber)

	var additionalData []byte
	if pkt.Header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&pkt.Header, len(payload))
	} else {
		additionalData = generateAEADAdditionalData(&pkt.Header, len(payload))
	}

	encryptedPayload := c.localCipher.Seal(nil, nonce, payload, additionalData)

	raw = append(raw, encryptedPayload...)

	binary.BigEndian.PutUint16(raw[pkt.Header.Size()-2:], uint16(len(raw)-pkt.Header.Size()))

	return raw, nil
}

func (c *ChaCha) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	if err := header.Unmarshal(in); err != nil {
		return nil, err
	}
	switch {
	case header.ContentType == protocol.ContentTypeChangeCipherSpec:
		return in, nil
	case len(in) <= header.Size():
		return nil, fmt.Errorf("not enough room for ciphertext")
	}

	out := in[header.Size():]

	nonce := buildNonce(c.remoteWriteIV, header.Epoch, header.SequenceNumber)

	var additionalData []byte
	if header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&header, len(out)-chacha20poly1305.Overhead)
	} else {
		additionalData = generateAEADAdditionalData(&header, len(out)-chacha20poly1305.Overhead)
	}

	plain, err := c.remoteCipher.Open(nil, nonce, out, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}
	return append(in[:header.Size()], plain...), nil
}

// generateAEADAdditionalData follows DTLS/TLS AEAD additional data format (13 bytes)
func generateAEADAdditionalData(h *recordlayer.Header, payloadLen int) []byte {
	var additionalData [13]byte
	seq64 := buildSeq64(h.Epoch, h.SequenceNumber)
	binary.BigEndian.PutUint64(additionalData[0:], seq64)
	additionalData[8] = byte(h.ContentType)
	additionalData[9] = h.Version.Major
	additionalData[10] = h.Version.Minor
	// length occupies last two bytes
	binary.BigEndian.PutUint16(additionalData[11:], uint16(payloadLen))
	return additionalData[:]
}

func generateAEADAdditionalDataCID(h *recordlayer.Header, payloadLen int) []byte {
	var builder cryptobyte.Builder

	// Use placeholder for 8 bytes seq as RFC9146 expects specific layout
	builder.AddUint64(seqNumPlaceholder)
	builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
	builder.AddUint8(uint8(len(h.ConnectionID))) // connection id len
	builder.AddUint8(uint8(protocol.ContentTypeConnectionID))
	builder.AddUint8(h.Version.Major)
	builder.AddUint8(h.Version.Minor)
	builder.AddUint16(h.Epoch)
	util.AddUint48(&builder, h.SequenceNumber)
	builder.AddBytes(h.ConnectionID)
	builder.AddUint16(uint16(payloadLen))

	return builder.BytesOrPanic()
}
