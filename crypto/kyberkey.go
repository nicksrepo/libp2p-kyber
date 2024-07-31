package crypto

import (
	"bytes"
	"encoding/base64"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
	"go.dedis.ch/kyber/v3/util/encoding"
	"io"
)

type KyberPrivateKey struct {
	priv  kyber.Scalar
	pub   kyber.Point
	suite anon.Suite
}

// NewKyberPrivateKey Generate new key pair
func NewKyberPrivateKey() (*KyberPrivateKey, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	privKey := suite.Scalar().Pick(suite.RandomStream())
	pubKey := suite.Point().Mul(privKey, nil)

	return &KyberPrivateKey{
		priv:  privKey,
		pub:   pubKey,
		suite: suite,
	}, nil
}

// Equals Implement crypto.PrivKey interface methods
func (k *KyberPrivateKey) Equals(other Key) bool {

	otherKeyBytes, err := other.Raw()
	if err != nil {
		return false
	}

	keyBytes, err := k.Raw()
	if err != nil {
		return false
	}

	return bytes.Equal(otherKeyBytes, keyBytes)
}

func (k *KyberPrivateKey) GetPublic() PubKey {
	return &KyberPublicKey{Pub: k.pub, Suite: k.suite}
}

func (k *KyberPrivateKey) Raw() ([]byte, error) {
	// Return raw bytes of the private key
	keyBytes, err := encoding.ScalarToStringHex(k.suite, k.priv)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(keyBytes))), nil

}

func (k *KyberPrivateKey) Type() pb.KeyType {
	// Return a custom key type or an existing one
	return pb.KeyType_KyberKey
}

func (k *KyberPrivateKey) Sign(data []byte) ([]byte, error) {
	X := make([]kyber.Point, 1)
	mine := 0
	X[mine] = k.pub
	sig := anon.Sign(k.suite, data, X, nil, mine, k.priv)
	return sig, nil
}

type KyberPublicKey struct {
	Pub   kyber.Point
	Suite anon.Suite
}

// Equals Implement crypto.PubKey interface methods
func (k *KyberPublicKey) Equals(other Key) bool {
	otherKeyBytes, err := other.Raw()
	if err != nil {
		return false
	}

	keyBytes, err := k.Raw()
	if err != nil {
		return false
	}

	return bytes.Equal(otherKeyBytes, keyBytes)
}

func (k *KyberPublicKey) Raw() ([]byte, error) {
	keyBytes, err := encoding.PointToStringHex(k.Suite, k.Pub)
	if err != nil {
		return nil, err
	}
	return []byte(keyBytes), nil

}

func (k *KyberPublicKey) Type() pb.KeyType {
	// Return a custom key type or an existing one
	return pb.KeyType_KyberKey
}

func (k *KyberPublicKey) Verify(data []byte, signature []byte) (bool, error) {
	// Implement verification logic, if supported by Kyber
	X := make([]kyber.Point, 1)
	X[0] = k.Pub
	tag, err := anon.Verify(k.Suite, data, X, nil, signature)
	if err != nil {
		return false, err
	}
	if err != nil {
		return false, err
	}
	if tag == nil || len(tag) != 0 {
		return false, err
	}
	return true, nil

}

// GenerateKyberKey generates a new ed25519 private and public key pair.
func GenerateKyberKey(src io.Reader) (PrivKey, PubKey, error) {
	priv, err := NewKyberPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	return priv, priv.GetPublic(), nil
}

// UnmarshalKyberPublicKey returns a public key from input bytes.
func UnmarshalKyberPublicKey(data []byte) (PubKey, error) {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	buf := bytes.NewBuffer(data)

	pointBytes, err := encoding.ReadHexPoint(suite, buf)
	if err != nil {
		return nil, err
	}
	return &KyberPublicKey{
		Pub:   pointBytes,
		Suite: suite,
	}, nil
}

func (k *KyberPublicKey) GetPub() kyber.Point {
	return k.Pub
}

// UnmarshalKyberPrivateKey  returns a private key from input bytes.
func UnmarshalKyberPrivateKey(data []byte) (PrivKey, error) {
	buf := bytes.NewBuffer(data)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalarBytes, err := encoding.ReadHexScalar(suite, buf)
	point := suite.Point().Mul(scalarBytes, nil)
	if err != nil {
		return nil, err
	}

	return &KyberPrivateKey{
		suite: suite,
		priv:  scalarBytes,
		pub:   point,
	}, nil
}
