package main

import (
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var curve = secp256k1.S256()
var field_size = curve.BitSize / 8

type Point struct {
	X *big.Int
	Y *big.Int
}

func (p *Point) Hash() *big.Int {
	buf := make([]byte, field_size*2)
	p.X.FillBytes(buf[:field_size])
	p.Y.FillBytes(buf[field_size:])
	h := sha256.Sum256(buf)
	v := new(big.Int).SetBytes(h[:])
	v.Mod(v, curve.N)
	return v
}

func (p *Point) IsOnCurve() bool {
	if p.X == nil || p.Y == nil {
		return false
	}
	return curve.IsOnCurve(p.X, p.Y)
}

func (p *Point) Add(q *Point) *Point {
	if p.X == nil || p.Y == nil {
		return q
	}
	if q.X == nil || q.Y == nil {
		return p
	}
	x, y := curve.Add(p.X, p.Y, q.X, q.Y)
	return &Point{X: x, Y: y}
}

func (p *Point) Mul(k *big.Int) *Point {
	if p.X == nil || p.Y == nil {
		return nil
	}
	if k.Sign() == 0 {
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}
	x, y := curve.ScalarMult(p.X, p.Y, k.Bytes())
	return &Point{X: x, Y: y}
}

func (p *Point) Neg() *Point {
	if p.X == nil || p.Y == nil {
		return nil
	}
	if p.Y.Sign() == 0 {
		return &Point{X: p.X, Y: big.NewInt(0)}
	}
	y2 := new(big.Int).Sub(curve.P, p.Y)
	return &Point{X: p.X, Y: y2}
}

func (p *Point) Sub(q *Point) *Point {
	if p.X == nil || p.Y == nil {
		return q.Neg()
	}
	if q.X == nil || q.Y == nil {
		return p
	}
	return p.Add(q.Neg())
}

func RandScalar() *big.Int {
	x, err := rand.Int(rand.Reader, curve.N)
	if err != nil {
		log.Fatal("Failed to generate random scalar:", err)
	}
	return x
}

func ComputeSeq(s *big.Int, n int) []*big.Int {
	ret := make([]*big.Int, 0, n)
	for i := 0; i < n; i++ {
		ret = append(ret, new(big.Int).Set(s))
		s.Add(s, big.NewInt(1))
		s.Mod(s, curve.N)
	}
	return ret
}

var G = Point{
	X: curve.Gx,
	Y: curve.Gy,
}

type GeneratorCtx struct {
	G    *Point
	Y    *Point
	cs   []*big.Int
	nYcs []*Point
	zs   []int
	Gzs  []*Point
}

func NewGeneratorCtx(pk *Point, k int, mx int) *GeneratorCtx {
	if !pk.IsOnCurve() {
		log.Fatal("Public key is not on the curve")
	}
	cs := ComputeSeq(big.NewInt(0), k)
	nYcs := make([]*Point, k)
	zs := make([]int, k)
	for i := 0; i < k; i++ {
		c := cs[i]
		nYcs[i] = pk.Mul(c).Neg()
		zs[i] = 0
	}
	Gz := &Point{
		X: nil,
		Y: nil,
	}
	Gzs := make([]*Point, mx)
	for i := 0; i < mx; i++ {
		Gzs[i] = Gz
		Gz = Gz.Add(&G)
	}
	return &GeneratorCtx{
		G:    &G,
		Y:    pk,
		cs:   cs,
		nYcs: nYcs,
		zs:   zs,
		Gzs:  Gzs,
	}
}

func (ctx *GeneratorCtx) Generate(n *big.Int, index int) *big.Int {
	// z := RandScalar()
	// Gr = G*z-Y*c
	// Gr := ctx.G.Mul(z).Sub(ctx.Ycs[index])
	nYc := ctx.nYcs[index]
	z := ctx.zs[index]
	Gz := ctx.Gzs[z]

	Gr := Gz.Add(nYc)

	h := Gr.Hash()

	// h = h.Mod(h, n)

	ctx.zs[index]++
	return h
}

func (ctx *GeneratorCtx) FindZ(index int, i int) int {
	// in the [index]th bucket, find the z for the [i]-th output
	return i
}

var targetPk *Point
var secp256k1Order = curve.N

func init() {
	pkX, _ := new(big.Int).SetString("693bd03b5825e4810053516404914d3daeacb4b4f4c01d4634bfbdaebb34483f", 16)
	pkY, _ := new(big.Int).SetString("b5996db62418ceb13196219660ad14ed26180ba5b46c42e4ff9e1254f631d5f7", 16)
	targetPk = &Point{
		X: pkX,
		Y: pkY,
	}
}
