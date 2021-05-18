package common

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

func TestCurve25519(t *testing.T) {
	signature, _ := hex.DecodeString("de50acf6fb875ab10b624a6a112c6f61f44bd7b72804229bcb926e9ebd54fe09088871a718b2e46949b4c59dcbd679c2105bd3142071ddb88023c8e75f99b00e")
	myPublic, _ := hex.DecodeString("2b7f55576ed18272920ea2507c22c303795a2059d61fc54d9b9aeb34a0991328")
	myMessage, _ := hex.DecodeString("9166a3819ea6cef333d89ca79b019c1446f0c3addf6d9a00b0c96c8c")
	b := VerifyMsg(myMessage, signature, myPublic, true)
	log.Println(b)
}

func TestDealine(t *testing.T) {
	gs, _ := hex.DecodeString("6ec823b5fd86c4aee9f7c3453cacaf4a43296f48ede77e70060ca8225c2855d0")
	scoop := CalculateScoop(gs, 500000)

	dealline := CalculateDeadline(4297397359864028267, 0, gs, scoop, 70312, 2)
	fmt.Println(scoop)
	fmt.Println(dealline)
}

func TestCryptoSha256(t *testing.T) {
	sum := Sum256([]byte("6ec823b5fd86c4aee9f7c3453cacaf4a43296f48ede77e70060ca8225c2855d0"))
	log.Printf("%v", sum)
	s1 := hex.EncodeToString(sum[0:])
	log.Printf("aec750d11feee9f16271922fbaf5a9be142f62019ef8d720f858940070889014 %s", s1)

	sum = Sum256([]byte("Testing"))
	s1 = hex.EncodeToString(sum[0:])
	log.Printf("10e237979a7233aa6a9377ff6a4b2541f890f67107fe0c89008fdd2c48e4cfe5 %s", s1)

	sha256 := NewDegist()
	sha256.Write([]byte("Burstcoin!"))
	b := make([]byte, 32)
	b = sha256.Sum(b[:0])
	s1 = hex.EncodeToString(b)
	log.Printf("9beec9e237da7542a045b89c709b5d423b22faa99d5f01abab67261e1a9de6b8 %s", s1)

	sha256.Reset()
	sha256.Write([]byte("Burst Apps Team"))
	a := make([]byte, 32)
	a = sha256.Sum(a[:0])
	s1 = hex.EncodeToString(a)
	log.Printf("4d92fb90793baaefabf4691cdcf4f1332ccd51c4a74f509a4b9a338eddb39e09 %s", s1)

}
