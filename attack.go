package SigAttack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sm/sm2"
	"math/big"
)

type dsaSignature struct {
	R, S *big.Int
}

type ecSignature dsaSignature

//type sm2Signature dsaSignature


// Given a signature and the public parameter N of the curve, generate another valid signature.
// When (r, s) is a vaild signature over (M, priv); then (r, -s) is also valid over (M, priv).

func GenerateECDSASig(sig *ecSignature, n *big.Int) *ecSignature {
	return &ecSignature{sig.R, new(big.Int).Sub(n, sig.S)}
}

// when sig is generated under digest = 0, recreate a valid signature for digest = 0
func ECDSAZeroHashAttack(sig *ecSignature, a *big.Int, c elliptic.Curve) *ecSignature {
	x3 := new(big.Int).Mul(sig.R, sig.R)
	x3.Mul(x3, sig.R)

	threeX := new(big.Int).Lsh(sig.R, 1)
	threeX.Add(threeX, sig.R)

	x3.Sub(x3, threeX)
	x3.Add(x3, c.Params().B)
	x3.Mod(x3, c.Params().P)

	y := new(big.Int).ModSqrt(x3, c.Params().P)

	r1, _ := c.ScalarMult(sig.R, y, a.Bytes())
	r1.Mod(r1, c.Params().N)

	sinv := new(big.Int).Mul(a, sig.R)
	sinv.ModInverse(sinv, c.Params().N)

	s1 := new(big.Int).Mul(new(big.Int).Mul(r1, sig.S), sinv)
	s1.Mod(s1, c.Params().N)

	return &ecSignature{r1, s1}
}

func ECDSAGenerateSignatureAttack(pub *ecdsa.PublicKey, a, b *big.Int) (r, s *big.Int, e []byte) {
	if b.Sign() == 0 {
		return nil, nil, nil
	}
	c := pub.Curve
	N := pub.Params().N
	aGx, aGy := c.ScalarBaseMult(a.Bytes()) // a * G
	bPx, bPy := c.ScalarMult(pub.X, pub.Y, b.Bytes()) // b * P

	r, _ = c.Add(aGx, aGy, bPx, bPy)
	r.Mod(r, N)

	bInv := new(big.Int).ModInverse(b, N)
	s = new(big.Int).Mul(r, bInv)
	s.Mod(s, N)

	tmp := new(big.Int).Mul(a, s)
	tmp.Mod(tmp, N)
	e = tmp.Bytes()
	return
}

// Given the public key, two signatures, and private linear relationship of generated random
// in ECDSA (e.g. rand2 = a * rand1 + b), generate the private key.

func RecoverECDSAPrivKeyFromLinearRelationship(pub *ecdsa.PublicKey, digest []byte, sig1, sig2 *ecSignature, a, b *big.Int) *ecdsa.PrivateKey {
	c := pub.Curve
	N := c.Params().N

	e := hashToInt(digest, c)
	w1 := new(big.Int).ModInverse(sig1.S, N) // s1^-1
	w2 := new(big.Int).ModInverse(sig2.S, N) // s2^-1
	w1.Mul(a, w1) // a * s1^-1
	e.Mul(e, new(big.Int).Sub(w2, w1)) // m * (s2^-1 - a * s1^-1)
	d1 := new(big.Int).Sub(b, e) // b - m * (s2^-1 - a * s1^-1)
	d1.Mod(d1, N)

	d2 := new(big.Int).Sub(new(big.Int).Mul(sig2.R, w2), new(big.Int).Mul(sig1.R, w1)) // r2 * s2^-1 - r1 * a * s1^-1
	if d2.Sign() == 0 {
		return nil
	}
	d2.ModInverse(d2, N)

	D := new(big.Int).Mul(d1, d2) // (b - m * (s2^-1 - a * s1^-1)) / (r2 * s2^-1 - r1 * a * s1^-1)
	D.Mod(D, N)

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey = *pub
	priv.D = D
	return priv
}


// Given the public key, two signatures, and private linear relationship of generated random
// in SM2 (e.g. rand2 = a * rand1 + b), generate the private key.

func RecoverSM2PrivKeyFromLinearRelationship(pub *sm2.PublicKey, sig1, sig2 *ecSignature, a, b *big.Int) *sm2.PrivateKey {
	c := pub.Curve
	N := c.Params().N

	t1 := new(big.Int).Add(sig1.S, sig1.R)
	t2 := new(big.Int).Add(sig2.S, sig2.R)

	dt := new(big.Int).Sub(t2, new(big.Int).Mul(a, t1)) // t2 - a * t1
	dt.Mod(dt, N)

	if dt.Sign() == 0 {
		return nil
	}

	ds := new(big.Int).Sub(sig2.S, new(big.Int).Mul(a, sig1.S)) // s2 - a * s1
	ds.Mod(ds, N)

	dt.ModInverse(dt, N)
	D := new(big.Int).Mul(new(big.Int).Sub(b, ds), dt) // (b - (s2 - a * s1)) / (t2 - a * t1)

	D.Mod(D, N)

	priv := new(sm2.PrivateKey)
	priv.PublicKey = *pub
	priv.D = D
	return priv
}


func RecoverSM2RandomRelationship(sig1, sig2 *ecSignature, N *big.Int) (a, b *big.Int) {
	t1 := new(big.Int).Add(sig1.S, sig1.R)
	t2 := new(big.Int).Add(sig2.S, sig2.R)

	t1Inv := t1.ModInverse(t1, N)
	if t1Inv == nil {
		return nil, nil
	}

	a = new(big.Int).Mul(t1Inv, t2)
	a.Mod(a, N)

	b = new(big.Int).Sub(sig2.S, new(big.Int).Mul(a, sig1.S))
	b.Mod(b, N)
	return
}

func RecoverSM2RandomFromPrivateKey(priv *sm2.PrivateKey, sig *ecSignature) *big.Int {

	s := new(big.Int).Mul(sig.S, new(big.Int).Add(new(big.Int).SetInt64(1), priv.D))
	k := s.Add(s, new(big.Int).Mul(sig.R, priv.D))
	return k.Mod(k, priv.Params().N)

}

func SM2GenerateSignatureAttack(pub *sm2.PublicKey, a, b *big.Int) (r, s *big.Int, e []byte) {
	c := pub.Curve
	N := pub.Params().N
	aGx, aGy := c.ScalarBaseMult(a.Bytes()) // a * G
	bPx, bPy := c.ScalarMult(pub.X, pub.Y, b.Bytes()) // b * P

	x, _ := c.Add(aGx, aGy, bPx, bPy)
	x.Mod(x, N)

	r = new(big.Int).Sub(b, a)
	r.Mod(r, N)
	s = new(big.Int).Set(a)
	s.Mod(s, N)

	tmp := new(big.Int).Sub(new(big.Int).Sub(b, x), a)
	tmp.Mod(tmp, N)
	e = tmp.Bytes()
	return
}


//func WeakGenerateKey(c elliptic.Curve, k *big.Int) (interface{}, error) {
//	switch c.Params().Name {
//	case "P-224", "P-256", "P-384", "P-521":
//		priv := new(ecdsa.PrivateKey)
//		priv.PublicKey.Curve = c
//		priv.D = k
//		priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
//		return priv, nil
//	case "SM2-P-256":
//		priv := new(sm2.PrivateKey)
//		priv.PublicKey.Curve = c
//		priv.D = k
//		priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
//		return priv, nil
//	}
//
//	return nil, errors.New("unkonwn curve")
//}

// [For Test] Sign a hashed message with a given random value
func WeakECDSASign(rand *big.Int, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int) {

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil
	}

	kInv := new(big.Int).ModInverse(rand, N)
	r, _ = priv.Curve.ScalarBaseMult(rand.Bytes())
	r.Mod(r, N)
	if r.Sign() == 0 {
		return nil, nil
	}
	e := hashToInt(hash, c)
	s = new(big.Int).Mul(priv.D, r)
	s.Add(s, e)
	s.Mul(s, kInv)
	s.Mod(s, N) // N != 0
	if s.Sign() == 0 {
		return nil, nil
	}
	return
}


// [For Test] Sign a hashed message with a given random value
func WeakSM2Sign(rand *big.Int, priv *sm2.PrivateKey, hash []byte) (r, s *big.Int) {

	var sm2P256 sm2.Sm2P256Curve
	e := new(big.Int).SetBytes(hash[0:32])
	n := priv.PublicKey.Curve.Params().N
	x1, _ := sm2P256.ScalarBaseMult(rand.Bytes())
	r = new(big.Int).Add(e, x1)
	r.Mod(r, n)
	if r.Sign() == 0 {
		return nil, nil
	}
	if t := new(big.Int).Add(r, rand); t.Cmp(n) == 0 {
		return nil, nil
	}
	s1 := new(big.Int).Mul(r, priv.D)
	s1.Mod(s1, n)
	s1.Sub(rand, s1)
	s1.Mod(s1, n)
	s2 := new(big.Int).Add(new(big.Int).SetInt64(1), priv.D)
	s2.Mod(s2, n)

	s2 = sm2P256.Inverse(s2)

	s = new(big.Int).Mul(s1, s2)
	s.Mod(s, n)
	if s.Sign() == 0 {
		return nil, nil
	}
	return
}

// Test function
//func WeakSM2Verify(pub *sm2.PublicKey, hash []byte, r, s *big.Int) bool {
//
//	c := pub.Curve
//	N := c.Params().N
//
//	if r.Sign() <= 0 || s.Sign() <= 0 {
//		return false
//	}
//	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
//		return false
//	}
//
//	n := pub.Curve.Params().N
//	e := new(big.Int).SetBytes(hash)
//	t := new(big.Int).Add(r, s)
//	t.Mod(t, n)
//
//	x1, y1 := pub.ScalarBaseMult(s.Bytes())
//	x2, y2 := pub.ScalarMult(pub.X, pub.Y, t.Bytes())
//	x, _ := pub.Add(x1, y1, x2, y2)
//	x.Add(e, x)
//	x.Mod(x, n)
//
//	return x.Cmp(r) == 0
//}

func MarshalSig(r, s *big.Int) *ecSignature {
	if r == nil && s == nil {
		return nil
	}
	return &ecSignature{r, s}
}

func ParseSig(sig *ecSignature) (r, s *big.Int) {
	if sig == nil {
		return nil, nil
	}
	return sig.R, sig.S
}


func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}