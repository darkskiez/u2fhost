// Package u2fhost provides a high level api for host applications to use u2f
package u2fhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

// ECPublicKey is an uncompressed ECDSA public key
type ECPublicKey [65]byte

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

type Client struct {
	FacetID      FacetID
	ErrorHandler func(error)
}

// NewClient will Generate a new Client from a given facet url
func NewClient(url string) Client {
	return Client{
		FacetID:      sha256.Sum256([]byte(url)),
		ErrorHandler: func(error) {},
	}
}

type KeyHandle []byte

type KeyHandler interface {
	KeyHandle() KeyHandle
}

type SignedKeyHandle struct {
	kh        KeyHandle
	PublicKey ECPublicKey
}

func (skh SignedKeyHandle) KeyHandle() KeyHandle {
	return skh.kh
}

// RegisterResponse contains the data from a token registration
// it is currently not validated!
type RegisterResponse struct {
	PublicKey       ECPublicKey
	KeyHandle       KeyHandle
	AttestationCert []byte
	Signature       ECSignatureBytes
}

func (r RegisterResponse) SignedKeyHandle() SignedKeyHandle {
	return SignedKeyHandle{kh: r.KeyHandle, PublicKey: r.PublicKey}
}

// AuthenticateResponse is returned when a token succesfully responds to
// an authentication request. Not currently validated!
type AuthenticateResponse struct {
	Counter   uint32
	Signature ECSignatureBytes
	// Convenience Fields
	KeyHandle
	KeyHandleIndex      int
	AuthenticateRequest u2ftoken.AuthenticateRequest
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

func parseRegisterResponse(data []byte) (RegisterResponse, error) {
	var r RegisterResponse
	// TODO: 68 + X509 min + signature min(32?)
	if len(data) < 100 {
		return r, errors.New("RegisterResponse: Too short")
	}
	if data[0] != 0x05 {
		return r, errors.New("RegisterResponse: Reserved byte != 0x05")
	}
	copy(r.PublicKey[:], data[1:66])
	khlen := int(data[66])
	if len(data) < 67+khlen {
		return r, errors.New("RegisterResponse: Too short for keyhandle length")
	}
	r.KeyHandle = data[67 : 67+khlen]

	// go x509/asn1 parsing explodes on ecdsa certs, this is a horrible kludge
	sigoffset, err := findSignatureOffset(data[67+khlen:])
	if err != nil {
		return r, errors.New("RegisterResponse: Couldnt parse signature")
	}

	r.AttestationCert = data[67+khlen : 67+khlen+sigoffset]
	r.Signature = data[67+khlen+sigoffset:]
	return r, nil
}

type token struct {
	*u2ftoken.Token
	Device *u2fhid.Device
}

func (t *token) Wink() error {
	return t.Device.Wink()
}

func (t *token) Close() {
	t.Device.Close()
}

var tokens = make(map[string]*token)

func (c Client) openTokens() map[string]*token {
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
		return tokens
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
			tokens[d.Path] = &token{Token: t, Device: dev}
		}
	}
	return tokens
}

func (c Client) closeTokens() {
	for p, d := range tokens {
		d.Close()
		delete(tokens, p)
	}
}

func getChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, challenge)
	return challenge, err
}

func (c Client) Register(ctx context.Context) (RegisterResponse, error) {
	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	defer c.closeTokens()

	challenge, err := getChallenge()
	if err != nil {
		return RegisterResponse{}, err
	}

	req := u2ftoken.RegisterRequest{Challenge: challenge, Application: c.FacetID[:]}

	r := make(chan RegisterResponse, 1)
	for {
		done := make(chan bool)
		go func() {
			c.openTokens()

			for _, t := range tokens {
				res, err := t.Register(req)
				if err == u2ftoken.ErrPresenceRequired {
					t.Wink()
				} else if err != nil {
					c.ErrorHandler(err)
				} else {
					resp, err := parseRegisterResponse(res)
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

// CheckAuthenticate returns true if any currently inserted token recognises any given keyhandle
func (c Client) CheckAuthenticate(ctx context.Context, keyhandlers []KeyHandler) (bool, error) {
	if len(keyhandlers) == 0 {
		return false, errors.New("No Keyhandles supplied")
	}

	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	defer c.closeTokens()

	challenge, err := getChallenge()
	if err != nil {
		return false, err
	}

	r := make(chan bool, 1)
	go func() {
		c.openTokens()
		for i := range keyhandlers {
			req := u2ftoken.AuthenticateRequest{
				Challenge:   challenge,
				Application: c.FacetID[:],
				KeyHandle:   keyhandlers[i].KeyHandle(),
			}
			for _, t := range tokens {
				err := t.CheckAuthenticate(req)
				if err == u2ftoken.ErrPresenceRequired || err == nil {
					r <- true
					return
				}
			}

		}
		r <- false
	}()
	select {
	case <-u2fctx.Done():
		return false, context.DeadlineExceeded
	case res := <-r:
		return res, nil
	}
}

// CheckAuthenticate returns a signed response if the user provides presence to a token that supplied a keyhandle
func (c Client) Authenticate(ctx context.Context, keyhandlers []KeyHandler) (AuthenticateResponse, error) {
	if len(keyhandlers) == 0 {
		return AuthenticateResponse{}, errors.New("No Keyhandles supplied")
	}

	u2fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	defer c.closeTokens()

	challenge, err := getChallenge()
	if err != nil {
		return AuthenticateResponse{}, err
	}

	deviceKeyHandles := make(map[string]map[int]int)
	r := make(chan AuthenticateResponse, 1)
	for {
		done := make(chan struct{})
		go func() {
			for i := range keyhandlers {
				req := u2ftoken.AuthenticateRequest{
					Challenge:   challenge,
					Application: c.FacetID[:],
					KeyHandle:   keyhandlers[i].KeyHandle(),
				}
				for p, t := range c.openTokens() {
					if deviceKeyHandles[p] == nil {
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
							deviceKeyHandles[p][i] = -1
							continue
						} else if err == u2ftoken.ErrPresenceRequired || err == nil {
							deviceKeyHandles[p][i] = 1
						}
					}

					res, err := t.Authenticate(req)
					if err == u2ftoken.ErrUnknownKeyHandle {
						deviceKeyHandles[p][i] = -1
						continue
					} else if err == u2ftoken.ErrPresenceRequired {
						t.Wink()
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
