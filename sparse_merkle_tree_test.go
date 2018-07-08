package mamamerkle

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var empty_val = bytes.Repeat([]byte{0x00}, 32)

var _hash = sha3.NewKeccak256()

func _keccak(value []byte) []byte {
	var buf []byte
	d := sha3.NewKeccak256()
	d.Write(value)
	buf = d.Sum(buf)
	return buf
}

func _keccakInt64(value int64) []byte {
	var bs = make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(value))
	return _keccak(bs)
}

var default_hash = _keccak(empty_val)
var dummy_val = _keccakInt64(2)
var dummy_val_2 = _keccakInt64(3)

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}

func TestSizeLimits(t *testing.T) {
	var leaves = make(map[uint64][]byte)
	leaves[0] = []byte{0}
	leaves[1] = []byte{1}
	_, err := NewSparseMerkleTree(0, leaves)
	require.NotNil(t, err)
}

func TestSizeLimits2(t *testing.T) {
	var leaves2 = make(map[uint64][]byte)
	leaves2[0] = empty_val
	leaves2[1] = empty_val
	leaves2[2] = empty_val
	_, err2 := NewSparseMerkleTree(1, leaves2)
	require.NotNil(t, err2)
}

func TestSMTEmptySMT(t *testing.T) {
	emptyTree1, _ := NewSparseMerkleTree(64, nil)
	emptyTree2, _ := NewSparseMerkleTree(64, map[uint64][]byte{})
	for _, emptyTree := range []*SparseMerkleTree{emptyTree1, emptyTree2} {
		require.Equal(t, 0, emptyTree.leaves.Len())
		require.Equal(t,
			"6f35419d1da1260bc0f33d52e8f6d73fc5d672c0dca13bb960b4ae1adec17937",
			hex.EncodeToString(emptyTree.root))
	}
}

func TestSMTAllLeavesWithVal(t *testing.T) {
	var leaves = make(map[uint64][]byte)
	leaves[0] = dummy_val
	leaves[1] = dummy_val
	leaves[2] = dummy_val
	leaves[3] = dummy_val

	smt, err := NewSparseMerkleTree(2, leaves)
	require.Nil(t, err)

	mid_level_val := _keccak(append(dummy_val, dummy_val...))
	mid_level_val = _keccak(append(mid_level_val, mid_level_val...))
	require.Equal(t, mid_level_val, smt.root)
}

func TestSMTEmptyLeaves(t *testing.T) {
	smt, err := NewSparseMerkleTree(2, nil)
	require.Nil(t, err)
	mid_level_val := _keccak(append(default_hash, default_hash...))
	mid_level_val = _keccak(append(mid_level_val, mid_level_val...))
	require.Equal(t, mid_level_val, smt.root)
}

func TestSMTEmptyLeftLeave(t *testing.T) {
	var leaves = make(map[uint64][]byte)
	leaves[1] = dummy_val
	leaves[2] = dummy_val
	leaves[3] = dummy_val

	mid_left_val := _keccak(append(default_hash, dummy_val...))
	mid_right_val := _keccak(append(dummy_val, dummy_val...))
	mid_level_val := _keccak(append(mid_left_val, mid_right_val...))

	smt, err := NewSparseMerkleTree(2, leaves)
	require.Nil(t, err)
	require.Equal(t, mid_level_val, smt.root)
}

func TestSMTEmptyRightLeave(t *testing.T) {
	var leaves = make(map[uint64][]byte)
	leaves[0] = dummy_val
	leaves[2] = dummy_val
	leaves[3] = dummy_val

	smt, err := NewSparseMerkleTree(2, leaves)
	require.Nil(t, err)

	mid_left_val := _keccak(append(dummy_val, default_hash...))
	mid_right_val := _keccak(append(dummy_val, dummy_val...))
	mid_level_val := _keccak(append(mid_left_val, mid_right_val...))
	require.Equal(t, mid_level_val, smt.root)
}

func TestSMTCreateMerkleProof(t *testing.T) {
	var leaves = make(map[uint64][]byte)
	leaves[0] = dummy_val
	leaves[2] = dummy_val
	leaves[3] = dummy_val_2

	smt, err := NewSparseMerkleTree(2, leaves)
	require.Nil(t, err)

	mid_left_val := _keccak(append(dummy_val, default_hash...))
	mid_right_val := _keccak(append(dummy_val, dummy_val_2...))

	proofBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(proofBytes, uint64(2))
	require.Equal(t, append(proofBytes, mid_right_val...), smt.CreateMerkleProof(uint64(0)))

	proofBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(proofBytes, uint64(3))
	tmp_val := append(dummy_val, mid_right_val...)
	require.Equal(t, append(proofBytes, tmp_val...), smt.CreateMerkleProof(uint64(1)))

	proofBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(proofBytes, uint64(3))
	tmp_val = append(dummy_val_2, mid_left_val...)
	require.Equal(t, append(proofBytes, tmp_val...), smt.CreateMerkleProof(uint64(2)))

	proofBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(proofBytes, uint64(3))
	tmp_val = append(dummy_val, mid_left_val...)
	require.Equal(t, append(proofBytes, tmp_val...), smt.CreateMerkleProof(uint64(3)))
}

func TestSMTVerification(t *testing.T) {
	slot := uint64(2)
	txHash := decodeHex("cf04ea8bb4ff94066eb84dd932f9e66d1c9f40d84d5491f5a7735200de010d84")
	slot2 := uint64(600)
	txHash2 := decodeHex("abcabcabacbc94566eb84dd932f9e66d1c9f40d84d5491f5a7735200de010d84")
	slot3 := uint64(30000)
	txHash3 := decodeHex("abcaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c9f40d84d5491f5a7735200de010d84")

	var tx = make(map[uint64][]byte)
	tx[slot] = txHash
	tx[slot2] = txHash2
	tx[slot3] = txHash3

	smt, err := NewSparseMerkleTree(64, tx)
	require.Nil(t, err)

	for k, _ := range tx {
		var proof = smt.CreateMerkleProof(k)
		inc, err := smt.Verify(k, proof)
		require.Nil(t, err)
		assert.True(t, inc)
	}
}

// TODO: Currently this test causes a panic because tree serialization/deserilization needs to be
//       updated after switching to uint64 leaves.
/*
func TestSMTSeriallization(t *testing.T) {

	//os.Exit(1)
	slot := uint64(2)
	txHash := decodeHex("cf04ea8bb4ff94066eb84dd932f9e66d1c9f40d84d5491f5a7735200de010d84")
	slot2 := uint64(600)
	txHash2 := decodeHex("abcabcabacbc94566eb84dd932f9e66d1c9f40d84d5491f5a7735200de010d84")
	slot3 := uint64(30000)
	txHash3 := decodeHex("abcaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c9f40d84d5491f5a7735200de010d84")

	var tx = make(map[uint64][]byte)
	tx[slot] = txHash
	tx[slot2] = txHash2
	tx[slot3] = txHash3

	smt, err := NewSparseMerkleTree(64, tx)
	require.Nil(t, err)
	data, err := smt.Serialize()
	require.Nil(t, err)

	smt2, err := LoadSparseMerkleTree(data)
	require.Nil(t, err)
	require.NotNil(t, smt2)

	for k, _ := range tx {
		var proof = smt2.CreateMerkleProof(k)
		inc, err := smt2.Verify(k, proof)
		require.Nil(t, err)
		assert.True(t, inc)
	}
	require.Equal(t, 32, len(smt2.root))
}
*/
func TestRealTreeRoots(t *testing.T) {
	slot := uint64(14414645988802088183)
	txHash := decodeHex("4b114962ecf0d681fa416dc1a6f0255d52d701ab53433297e8962065c9d439bd")
	leaves := make(map[uint64][]byte)
	leaves[slot] = txHash
	smt, err := NewSparseMerkleTree(64, leaves)
	require.Nil(t, err)
	require.Equal(t, "0ed6599c03641e5a20d9688f892278dbb48bbcf8b1ff2c9a0e2b7423af831a83", hex.EncodeToString(smt.root))

	slot = uint64(14414645988802088183)
	txHash = decodeHex("510a183d5457e0d22951440a273f0d8e28e01d15f750d79fd1b27442299f7220")
	leaves = make(map[uint64][]byte)
	leaves[slot] = txHash
	smt, err = NewSparseMerkleTree(64, leaves)
	require.Nil(t, err)
	require.Equal(t, "8d0ae4c94eaad54df5489e5f9d62eeb4bf06ff774a00b925e8a52776256e910f", hex.EncodeToString(smt.root))
}
