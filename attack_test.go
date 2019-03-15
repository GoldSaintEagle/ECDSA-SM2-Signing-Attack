package SigAttack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sm/sm2"
	"fmt"
	"io"
	"math/big"
	"testing"
)

func TestGenerateECDSASig(t *testing.T) {

	// Generate key pair
	p256 := elliptic.P256()
	priv, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		t.Errorf("Error generating key: %s", err)
		return
	}

	// message
	hashed := []byte("12345678")

	// Generate signature
	r1, s1, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("Error signing: %s", err)
		return
	}

	// verify original signature
	if !ecdsa.Verify(&priv.PublicKey, hashed, r1, s1) {
		t.Errorf("Error verifying")
		return
	}
	sig1 := MarshalSig(r1, s1)

	// generate new signature
	sig2 := GenerateECDSASig(sig1, priv.PublicKey.Params().N)
	r2, s2 := ParseSig(sig2)

	// verify new signature
	if !ecdsa.Verify(&priv.PublicKey, hashed, r2, s2) {
		t.Errorf("Error verifying")
		return
	}

	fmt.Printf("Both sig1 and sig2 pass verification.\nsig1: %v\nsig2: %v\n", sig1, sig2)

	return
}


func TestRecoverECDSAPrivKeyFromLinearRelationship(t *testing.T) {
	// Generate key pair
	p256 := elliptic.P256()
	priv, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		t.Errorf("Error generating key: %s", err)
		return
	}
	fmt.Printf(" original priv: %v\n", priv)

	// message
	hashed := []byte("12345678")

	// Random relationship
	a := new(big.Int).SetInt64(22)
	b := new(big.Int).SetInt64(34)
	k := make([]byte, priv.Params().BitSize/8+8)
	_, err = io.ReadFull(rand.Reader, k)
	if err != nil {
		return
	}
	rand1 := new(big.Int).SetBytes(k)
	rand2 := new(big.Int).Mul(a, rand1)
	rand2.Add(rand2, b)


	// Generate signature 1
	r1, s1 := WeakECDSASign(rand1, priv, hashed)
	if r1 == nil || s1 == nil {
		t.Errorf("Invalid random 1 to generate signature: %x", rand1)
		return
	}
	sig1 := MarshalSig(r1, s1)

	// Generate signature 2
	r2, s2 := WeakECDSASign(rand2, priv, hashed)
	if r2 == nil || s2 == nil {
		t.Errorf("Invalid random 2 to generate signature: %x", rand2)
		return
	}
	sig2 := MarshalSig(r2, s2)

	// Recover private key
	rpriv := RecoverECDSAPrivKeyFromLinearRelationship(&priv.PublicKey, hashed, sig1, sig2, a, b)
	if rpriv == nil {
		fmt.Printf("Unable to recover.\n")
	} else {
		fmt.Printf("recovered priv: %v\n", rpriv)
	}
}


func TestRecoverSM2PrivKeyFromLinearRelationship(t *testing.T) {
	// Generate key pair
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Error generating key: %s", err)
		return
	}
	fmt.Printf(" original priv: %v\n", priv)

	// message
	hashed := []byte("12345678")

	// Random relationship
	a := new(big.Int).SetInt64(0)
	b := new(big.Int).SetInt64(0)
	k := make([]byte, priv.Params().BitSize/8+8)
	_, err = io.ReadFull(rand.Reader, k)
	if err != nil {
		return
	}
	rand1 := new(big.Int).SetBytes(k)
	rand2 := new(big.Int).Mul(a, rand1)
	rand2.Add(rand2, b)


	// Generate signature 1
	r1, s1 := WeakSM2Sign(rand1, priv, hashed)
	if r1 == nil || s1 == nil {
		t.Errorf("Invalid random 2 to generate signature: %s", rand1)
		return
	}
	sig1 := MarshalSig(r1, s1)

	// Generate signature 2
	r2, s2 := WeakSM2Sign(rand2, priv, hashed)
	if r2 == nil || s2 == nil {
		t.Errorf("Invalid random 2 to generate signature: %s", rand2)
		return
	}
	sig2 := MarshalSig(r2, s2)


	ra, rb := RecoverSM2RandomRelationship(sig1, sig2, priv.Params().N)

	fmt.Printf("Random relationship : %v %v\n", ra, rb)

	// Recover private key
	rpriv := RecoverSM2PrivKeyFromLinearRelationship(&priv.PublicKey, sig1, sig2, a, b)
	fmt.Printf("recovered priv: %v\n", rpriv)

	rpriv2 := RecoverSM2PrivKeyFromLinearRelationship(&priv.PublicKey, sig1, sig2, ra, rb)
	if rpriv2 == nil {
		fmt.Printf("Unable to recover.\n")
	} else {
		fmt.Printf("recovered priv: %v\n", rpriv)
	}
}

func TestRecoverSM2RandomFromPrivateKey(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	k := new(big.Int).SetInt64(222)
	hashed := []byte("12345678")

	r, s := WeakSM2Sign(k, priv, hashed)
	sig := MarshalSig(r, s)
	rk := RecoverSM2RandomFromPrivateKey(priv, sig)
	if rk.Cmp(k) != 0 {
		t.Errorf("Error recovery frandom")
		return
	}
	fmt.Printf("Rand : %v.\n", k)
	return
}


func TestECDSAZeroHashAttack(t *testing.T) {
	p256 := elliptic.P256()
	priv, _ := ecdsa.GenerateKey(p256, rand.Reader)
	hashed := []byte{0}
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hashed)
	sig := MarshalSig(r, s)
	fmt.Printf("sig1: %v\n", sig)
	a := new(big.Int).SetInt64(3)
	sig2 := ECDSAZeroHashAttack(sig, a, priv.Curve)
	fmt.Printf("sig2: %v\n", sig2)
	if !ecdsa.Verify(&priv.PublicKey, hashed, sig2.R, sig2.S) {
		t.Errorf("Error verifying")
		return
	}
	fmt.Printf("sig2 pass verification.\n")
	return
}

func TestSM2GenerateSignatureAttack(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	// a != 0 && b != a
	a := new(big.Int).SetInt64(1)
	b := new(big.Int).SetInt64(2)

	r, s, hashed := SM2GenerateSignatureAttack(&priv.PublicKey, a, b)
	if !sm2.Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Error verifying")
		return
	}
	fmt.Printf("generated sig pass verification.\n")
	return
}

func TestECDSAGenerateSignatureAttack(t *testing.T) {
	p256 := elliptic.P256()
	priv, _ := ecdsa.GenerateKey(p256, rand.Reader)
	// b != 0
	a := new(big.Int).SetInt64(0)
	b := new(big.Int).SetInt64(444)

	r, s, hashed := ECDSAGenerateSignatureAttack(&priv.PublicKey, a, b)
	if !ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Error verifying")
		return
	}
	fmt.Printf("generated sig pass verification.\n")
	return
}

