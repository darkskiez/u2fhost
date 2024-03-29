// Package u2fhost provides a high level api for host applications to use u2f
package u2fhost

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var KeyNotFoundError = errors.New("matching key not found")
var NoKeysInsertedError = errors.New("no security keys inserted")

// ecPublicKeyBytes is an uncompressed ECDSA public key
type ecPublicKeyBytes [65]byte

func (ecpk ecPublicKeyBytes) ECPublicKey() *ecdsa.PublicKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), ecpk[:])
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

// ECSignatureBytes is a DER Encoded Signature, 70-72 bytes
type ECSignatureBytes []byte

// ECSignature is an unpacked ECDSA Signature
type ECSignature struct {
	R *big.Int
	S *big.Int
}

// ECSignature will decode a DER signature
func (ec ECSignatureBytes) ECSignature() (ECSignature, error) {
	var sig ECSignature
	// TODO: work around golangs strict asn1
	_, err := asn1.Unmarshal(ec, &sig)
	return sig, err
}

// FacetID is aka ApplicationID
type FacetID [32]byte

// ClientInterface defines this api, consume this to switch with test mocks
type ClientInterface interface {
	Authenticate(ctx context.Context, clientdata string, keyhandlers []KeyHandler) (AuthenticateResponse, error)
	CheckAuthenticate(ctx context.Context, clientdata string, keyhandlers []KeyHandler) (int, error)
	Register(ctx context.Context, clientdata string) (RegisterResponse, error)
	Facet() []byte
}

// Client holds the application u2f client state
// The ErrorHandler is to give applications visibility of transient errors
// that may occur for logging or other purposes.
type Client struct {
	FacetID      FacetID
	ErrorHandler func(error)
}

// Facet returns the U2F facet url hash as bytes.
func (c Client) Facet() []byte {
	return c.FacetID[:]
}

// NewClient will Generate a new Client from a given facet url
func NewClient(url string) Client {
	return Client{
		FacetID:      sha256.Sum256([]byte(url)),
		ErrorHandler: func(error) {},
	}
}

// KeyHandle is the byte sequence returned by a u2f device on registration
// that is required to be returned to it for authentication
type KeyHandle []byte

// KeyHandler is an interface to obtain a Keyhandle for authentication
type KeyHandler interface {
	KeyHandle() KeyHandle
}

// KeyHandle allows using the base type directly
func (k KeyHandle) KeyHandle() KeyHandle {
	return k
}

// RegisterResponse contains the data from a token registration
// Call CheckSignature on the response to validate
type RegisterResponse struct {
	PublicKey       *ecdsa.PublicKey
	KeyHandle       KeyHandle
	AttestationCert []byte
	Signature       ECSignatureBytes

	// fields from request, required to verify
	publicKey ecPublicKeyBytes
	challenge []byte
	facetID   FacetID
}

// CheckSignature verifies if the RegisterResponse Signature matches the AttestationCert
// nolint:gosec
func (r RegisterResponse) CheckSignature() error {
	c, err := x509.ParseCertificate(r.AttestationCert)
	if err != nil {
		return err
	}

	b := bytes.NewBuffer(nil)
	b.Write([]byte{0})
	b.Write(r.facetID[:])
	b.Write(r.challenge)
	b.Write(r.KeyHandle)
	b.Write(r.publicKey[:])
	err = c.CheckSignature(x509.ECDSAWithSHA256, b.Bytes(), r.Signature[:])
	return err
}

// AuthenticateResponse is returned when a token succesfully responds to
// an authentication request.
// Call CheckSignature on the response to validate
type AuthenticateResponse struct {
	Counter   uint32
	Signature ECSignatureBytes
	// Convenience Fields
	KeyHandle
	KeyHandleIndex      int
	AuthenticateRequest u2ftoken.AuthenticateRequest
}

// CheckSignature checks if the Authentication matches the signature against the provided public key
// nolint:gosec
func (a AuthenticateResponse) CheckSignature(pubkey *ecdsa.PublicKey) error {
	h := sha256.New()
	h.Write(a.AuthenticateRequest.Application)
	h.Write([]byte{0x01})                        // Presence
	binary.Write(h, binary.BigEndian, a.Counter) // nolint:errcheck
	h.Write(a.AuthenticateRequest.Challenge)
	sig, err := a.Signature.ECSignature()
	if err != nil {
		return err
	}
	if !ecdsa.Verify(pubkey, h.Sum(nil), sig.R, sig.S) {
		return errors.New("ecdsa signature validation failed")
	}
	return nil
}

// ecdsa der signatures are 70,71,72 bytes, try each in turn to parse a signature
func findSignatureOffset(data []byte) (int, error) {
	sig := struct {
		R *big.Int
		S *big.Int
	}{}

	offset := len(data) - 72

	for i := 0; i < 3; i++ {
		_, err := asn1.Unmarshal(data[offset+i:], &sig)
		if err == nil {
			return offset + i, nil
		}
	}

	return 0, errors.New("Couldnt find signature")
}

func parseRegisterResponse(req u2ftoken.RegisterRequest, data []byte) (RegisterResponse, error) {
	var r RegisterResponse
	// TODO: 68 + X509 min + signature min(32?)
	if len(data) < 100 {
		return r, errors.New("RegisterResponse: Too short")
	}
	if data[0] != 0x05 {
		return r, errors.New("RegisterResponse: Reserved byte != 0x05")
	}
	copy(r.publicKey[:], data[1:66])
	r.PublicKey = r.publicKey.ECPublicKey()

	khlen := int(data[66])
	if len(data) < 67+khlen {
		return r, errors.New("RegisterResponse: Too short for keyhandle length")
	}
	r.KeyHandle = data[67 : 67+khlen]

	// We dont know the length of the certificate and go wont parse it with
	// trailing data, so find the signature at the end and use that
	sigoffset, err := findSignatureOffset(data[67+khlen:])
	if err != nil {
		return r, errors.New("RegisterResponse: Couldnt parse signature")
	}

	r.AttestationCert = data[67+khlen : 67+khlen+sigoffset]
	r.Signature = data[67+khlen+sigoffset:]

	r.challenge = req.Challenge
	copy(r.facetID[:], req.Application)
	return r, nil
}

type token struct {
	*u2ftoken.Token
	Device *u2fhid.Device
	Path   string
}

func (t *token) Wink() error {
	return t.Device.Wink()
}

func (t *token) Close() {
	t.Device.Close()
}

func (c Client) refreshTokenMap(tokens map[string]*token) {
	// Clean up dead devices
	for p, d := range tokens {
		if _, err := d.Device.Ping([]byte{0x01}); err != nil {
			d.Close()
			delete(tokens, p)
		}
	}

	// Enumerate new devices
	devices, err := u2fhid.Devices()
	if err != nil {
		c.ErrorHandler(err)
		return
	}

	for _, d := range devices {
		if tokens[d.Path] != nil {
			continue
		}
		dev, err := u2fhid.Open(d)
		if err != nil {
			// not fatal, may be one of many tokens
			c.ErrorHandler(err)
			continue
		}
		t := u2ftoken.NewToken(dev)
		version, err := t.Version()
		if err != nil {
			c.ErrorHandler(err)
			dev.Close()
		} else if version == "U2F_V2" {
			tokens[d.Path] = &token{Token: t, Device: dev, Path: d.Path}
		}
	}
}

func (c Client) tokenGenerator(ctx context.Context) chan *token {
	ch := make(chan *token)
	go func() {
		tokens := make(map[string]*token)
		for {
			c.refreshTokenMap(tokens)
			for _, t := range tokens {
				select {
				case <-ctx.Done():
					close(ch)
					return
				case ch <- t:
				}
			}
		}
	}()
	return ch
}

// Register will generate a RegisterResponse if a U2F token is touched.
func (c Client) Register(ctx context.Context, clientdata string) (RegisterResponse, error) {
	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	challenge := sha256.Sum256([]byte(clientdata))

	req := u2ftoken.RegisterRequest{Challenge: challenge[:], Application: c.FacetID[:]}

	r := make(chan RegisterResponse, 1)
	for {
		done := make(chan bool)
		go func() {

			for t := range c.tokenGenerator(u2fctx) {
				res, err := t.Register(req)
				if err == u2ftoken.ErrPresenceRequired {
					_ = t.Wink() // nolint
				} else if err != nil {
					c.ErrorHandler(err)
				} else {
					resp, err := parseRegisterResponse(req, res)
					if err != nil {
						c.ErrorHandler(err)
					} else {
						r <- resp
						break
					}
				}
			}
			close(done)
		}()
		select {
		case <-u2fctx.Done():
			return RegisterResponse{}, context.DeadlineExceeded
		case res := <-r:
			return res, nil
		case <-done:
			time.Sleep(200 * time.Millisecond)
		}
	}

}

// CheckAuthenticate returns the index if any currently inserted token recognises any given keyhandle or an error
func (c Client) CheckAuthenticate(ctx context.Context, clientdata string, keyhandlers []KeyHandler) (int, error) {
	if len(keyhandlers) == 0 {
		return 0, errors.New("No KeyHandles supplied")
	}

	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	challenge := sha256.Sum256([]byte(clientdata))

	tokens := make(map[string]*token)
	c.refreshTokenMap(tokens)
	if len(tokens) == 0 {
		return -2, NoKeysInsertedError
	}

	r := make(chan int, 1)
	go func() {
		for i := range keyhandlers {
			req := u2ftoken.AuthenticateRequest{
				Challenge:   challenge[:],
				Application: c.FacetID[:],
				KeyHandle:   keyhandlers[i].KeyHandle(),
			}

			for _, t := range tokens {
				err := t.CheckAuthenticate(req)
				if err == u2ftoken.ErrPresenceRequired || err == nil {
					r <- i
					return
				}
			}

		}
		r <- -1
	}()
	select {
	case <-u2fctx.Done():
		return -1, context.DeadlineExceeded
	case res := <-r:
		if res < 0 {
			return -1, KeyNotFoundError
		}
		return res, nil
	}
}

// Authenticate returns a signed response if the user provides presence to a token that supplied a keyhandle
func (c Client) Authenticate(ctx context.Context, clientdata string, keyhandlers []KeyHandler) (AuthenticateResponse, error) {
	if len(keyhandlers) == 0 {
		return AuthenticateResponse{}, errors.New("No Keyhandles supplied")
	}

	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	challenge := sha256.Sum256([]byte(clientdata))

	deviceKeyHandles := make(map[string]map[int]int)
	r := make(chan AuthenticateResponse, 1)
	for {
		done := make(chan struct{})
		go func() {
			for t := range c.tokenGenerator(u2fctx) {
				for i := range keyhandlers {
					req := u2ftoken.AuthenticateRequest{
						Challenge:   challenge[:],
						Application: c.FacetID[:],
						KeyHandle:   keyhandlers[i].KeyHandle(),
					}
					p := t.Path
					if deviceKeyHandles[p] == nil {
						//log.Printf("Found token %v\n", t.Path)
						deviceKeyHandles[p] = make(map[int]int)
					}
					if deviceKeyHandles[p][i] == -1 {
						continue
					}

					// This call to Check shouldnt be necessary; the api should return
					// the real error in authenticate call too
					if deviceKeyHandles[p][i] == 0 {
						err := t.CheckAuthenticate(req)
						if err == u2ftoken.ErrUnknownKeyHandle {
							//log.Printf("Bad token/kh %v %v\n", t.Path, i)
							deviceKeyHandles[p][i] = -1
							continue
						} else if err == u2ftoken.ErrPresenceRequired || err == nil {
							//log.Printf("Presence Needed token/kh %v %v\n", t.Path, i)
							deviceKeyHandles[p][i] = 1
						}
					}

					res, err := t.Authenticate(req)
					if err == u2ftoken.ErrUnknownKeyHandle {
						deviceKeyHandles[p][i] = -1
						continue
					} else if err == u2ftoken.ErrPresenceRequired {
						_ = t.Wink() // nolint
					} else if err != nil {
						c.ErrorHandler(err)
					} else {
						r <- AuthenticateResponse{
							AuthenticateRequest: req,
							Counter:             res.Counter,
							Signature:           res.Signature,
							KeyHandle:           keyhandlers[i].KeyHandle(),
							KeyHandleIndex:      i,
						}
					}
				}
			}
			close(done)
		}()
		select {
		case <-u2fctx.Done():
			return AuthenticateResponse{}, context.DeadlineExceeded
		case res := <-r:
			return res, nil
		case <-done:
			time.Sleep(200 * time.Millisecond)
		}
	}

}

var _ ClientInterface = Client{}
