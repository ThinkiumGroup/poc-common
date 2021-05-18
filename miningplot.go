package common

import (
	"encoding/binary"
	"math/big"
)

const (
	HASH_SIZE        int = 32
	HASHES_PER_SCOOP int = 2
	SCOOP_SIZE       int = 64
	SCOOPS_PER_PLOT  int = 4096
	PLOT_SIZE        int = 262144
	BASE_LENGTH      int = 16
	PLOT_TOTAL_SIZE  int = PLOT_SIZE + BASE_LENGTH
	HASH_CAP         int = 4096

	pocVersion2 = 2
)

var SCOOPS_PER_PLOT_BIGINT *big.Int = big.NewInt(int64(SCOOPS_PER_PLOT))

type MiningPlot struct {
	data []byte
}

func NewMiningPlot(accountId uint64, nonce uint64, pocVersion int) *MiningPlot {
	mp := new(MiningPlot)
	mp.data = make([]byte, PLOT_TOTAL_SIZE)
	binary.BigEndian.PutUint64(mp.data[PLOT_SIZE:], accountId)
	binary.BigEndian.PutUint64(mp.data[PLOT_SIZE+8:], nonce)

	digist := NewDegist()
	for i := PLOT_SIZE; i > 0; i -= HASH_SIZE {
		len := PLOT_TOTAL_SIZE - i
		if len > HASH_CAP {
			len = HASH_CAP
		}
		digist.Write1(mp.data, uint32(i), len)
		sum := make([]byte, 32)
		sum = digist.Sum(sum[:0])
		digist.Reset()
		idx := i - HASH_SIZE
		copy(mp.data[idx:], sum)
	}

	finalHash := Sum256(mp.data)
	digist.Reset()

	i := 0
	var revPos int
	for revPos = 0; i < PLOT_SIZE; revPos++ {
		if revPos == HASH_SIZE {
			revPos = 0
		}
		mp.data[i] ^= finalHash[revPos]
		i++
	}

	if pocVersion == pocVersion2 {
		var hashBuffer [32]byte
		revPos = PLOT_SIZE - HASH_SIZE

		for pos := 32; pos < PLOT_SIZE/HASHES_PER_SCOOP; pos += 64 {
			copy(hashBuffer[0:], mp.data[pos:pos+HASH_SIZE])
			copy(mp.data[pos:], mp.data[revPos:revPos+HASH_SIZE])
			copy(mp.data[revPos:], hashBuffer[0:HASH_SIZE])
			revPos -= 64
		}
	}
	return mp
}

func (mp *MiningPlot) HashScoop(digist *Digest, pos int) {
	digist.Write1(mp.data, uint32(pos*SCOOP_SIZE), SCOOP_SIZE)
}

func CalculateGenerationSignature(lastGenSig []byte, lastGenId uint64) []byte {
	digist := NewDegist()
	digist.Write(lastGenSig)
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, lastGenId)
	digist.Write(bytes)
	sum := make([]byte, 32)
	return digist.Sum(sum[:0])
}

func CalculateScoop(genSig []byte, height uint64) int {
	digist := NewDegist()
	digist.Write(genSig)

	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, height)
	digist.Write(bytes)

	sum := make([]byte, 32)
	sum = digist.Sum(sum[:0])

	hashnum := big.NewInt(0).SetBytes(sum)
	m := big.NewInt(0).Mod(hashnum, SCOOPS_PER_PLOT_BIGINT)
	return int(m.Int64())
}

func CalculateHit(accountId uint64, nonce uint64, genSig []byte, scoop int, pocVersion int) uint64 {
	mp := NewMiningPlot(accountId, nonce, pocVersion)
	digist := NewDegist()
	digist.Write(genSig)
	mp.HashScoop(digist, scoop)
	sum := make([]byte, 32)
	sum = digist.Sum(sum[:0])
	rev := []byte{sum[7], sum[6], sum[5], sum[4], sum[3], sum[2], sum[1], sum[0]}
	ret := binary.BigEndian.Uint64(rev)
	return ret
}

func CalculateDeadline(accountId uint64, nonce uint64, genSig []byte, scoop int, baseTarget uint64, pocVersion int) uint64 {
	hit := CalculateHit(accountId, nonce, genSig, scoop, pocVersion)
	return hit / baseTarget
}

func CalculateDeadlineOfPoc2(accountId uint64, nonce uint64, genSig [32]byte, height uint64, baseTarget uint64) uint64 {
	scoop := CalculateScoop(genSig[:], height)
	return CalculateDeadline(accountId, nonce, genSig[:], scoop, baseTarget, pocVersion2)
}
