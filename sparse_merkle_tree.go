package mamamerkle

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/cevaris/ordered_map"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"io"
	"github.com/ethereum/go-ethereum/rlp"
)

type SparseMerkleTree struct {
	depth        int64
	leaves       *ordered_map.OrderedMap
	root         []byte
	tree         []*ordered_map.OrderedMap
	defaultNodes [][]byte
}

func (smt *SparseMerkleTree) keccak(value []byte) []byte {
	var buf []byte
	d := sha3.NewKeccak256()
	d.Write(value)
	buf = d.Sum(buf)
	return buf
}

func (smt *SparseMerkleTree) Depth() int64 {
	return smt.depth
}

func (smt *SparseMerkleTree) Root() []byte {
	return smt.root
}

func (smt *SparseMerkleTree) CreateDefaultNodes(depth int64) [][]byte {

	defaultHash := smt.keccak(bytes.Repeat([]byte{0x00}, 32))
	defaultNodes := [][]byte{defaultHash}

	for level := int64(1); level < smt.depth; level++ {
		prevDefault := defaultNodes[level-1]
		nextDefault := smt.keccak(append(prevDefault, prevDefault...))
		defaultNodes = append(defaultNodes, nextDefault)

	}

	return defaultNodes
}

func (smt *SparseMerkleTree) CreateTree(orderedLeaves *ordered_map.OrderedMap, depth int64, defaultNodes [][]byte) []*ordered_map.OrderedMap {
	tree := []*ordered_map.OrderedMap{orderedLeaves}
	treeLevel := orderedLeaves
	for level := int64(0); level < depth-1; level++ {
		nextLevel := ordered_map.NewOrderedMap()
		prevIndex := int64(-1)
		levelsIter := treeLevel.IterFunc()

		for KV, ok := levelsIter(); ok; KV, ok = levelsIter() {

			index, ok := KV.Key.(int64)
			if !ok {
				panic("Non integer key found")
			}
			value, ok := KV.Value.([]byte)
			if !ok {
				panic("Non []byte value found")
			}

			if index%2 == 0 {
				// If the node is a left node, assume the right sibling is
				// a default node. In the case right sibling is not default
				// node, it would override on next round
				nextLevel.Set(index/2, smt.keccak(append(value, defaultNodes[level]...)))

			} else {
				// If the node is a right node, check if its left sibling is
				// a default node.
				if index == prevIndex+int64(1) {
					tmp, _ := treeLevel.Get(prevIndex)
					nextLevel.Set(index/2, smt.keccak(append(tmp.([]byte), value...)))
				} else {
					nextLevel.Set(index/2, smt.keccak(append(defaultNodes[level], value...)))
				}

			}

			prevIndex = index
		}

		treeLevel = nextLevel
		tree = append(tree, treeLevel)
	}

	return tree
}

func (smt *SparseMerkleTree) CreateMerkleProof(leafId int64) []byte {
	// Generate a merkle proof for a leaf with provided index.
	// First `depth/8` bytes of the proof are necessary for checking if
	// we are at a default-node
	index := leafId
	proof := []byte("")
	var proofbits uint64 = 0
	for level := int64(0); level < smt.depth-1; level++ {
		var siblingIndex int64
		if index%2 == 0 {
			siblingIndex = index + 1
		} else {
			siblingIndex = index - 1
		}

		index = index / 2
		if value, ok := smt.tree[level].Get(siblingIndex); ok {
			proof = append(proof, value.([]byte)...)
			proofbits += uint64(math.Pow(2, float64(level)))
		}

	}

	proofBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(proofBytes, proofbits)

	proofBytes = append(proofBytes, proof...)
	return proofBytes
}

// Checks if the proof for the leaf at `uid` is valid
func (smt *SparseMerkleTree) Verify(leafId int64, proof []byte) (bool, error) {
	if ((len(proof) - 8) % 32) != 0 {
		return false, errors.New("invalid proof length `len(proof) - 8` must be a multiple of 32")
	}
	if len(proof) > 2056 {
		return false, errors.New("invalid proof length Must be less than 2056")
	}

	proofbits := binary.BigEndian.Uint64(proof[0:8])
	index := leafId
	p := 8

	if _, ok := smt.leaves.Get(index); ok == false {
		return false, errors.New("leaf index out of range")
	}
	computedHashRaw, _ := smt.leaves.Get(index)
	computedHash := computedHashRaw.([]byte)
	var proofElement []byte
	for d := int64(0); d < smt.depth-1; d++ {
		if proofbits%2 == 0 {
			proofElement = make([]byte, len(smt.defaultNodes[d]))
			copy(proofElement, smt.defaultNodes[d])
		} else {
			proofElement = make([]byte, len(proof[p:p+32]))
			copy(proofElement, proof[p:p+32])
			p += 32
		}
		if index%2 == 0 {
			computedHash = smt.keccak(append(computedHash, proofElement...))
		} else {
			computedHash = smt.keccak(append(proofElement, computedHash...))
		}

		proofbits = proofbits / 2
		index = index / 2

	}
	return bytes.Equal(computedHash, smt.root), nil
}

func (smt *SparseMerkleTree) serializeOrderedMap(om *ordered_map.OrderedMap) []map[string]interface{} {
	var om_array []map[string]interface{}
	levelsIter := om.IterFunc()
	for KV, ok := levelsIter(); ok; KV, ok = levelsIter() {
		var kv_bytes = make(map[string]interface{})
		kv_bytes["key"] = KV.Key.(int64)
		kv_bytes["value"] = hex.EncodeToString(KV.Value.([]byte))
		om_array = append(om_array, kv_bytes)
	}
	return om_array
}

func (smt *SparseMerkleTree) serializeOrderedMapRaw(om *ordered_map.OrderedMap) [][]interface{} {
	var om_array [][]interface{}
	levelsIter := om.IterFunc()
	for KV, ok := levelsIter(); ok; KV, ok = levelsIter() {
		var kv_bytes []interface{}
		kv_bytes = append(kv_bytes, uint64(KV.Key.(int64)))
		kv_bytes = append(kv_bytes, KV.Value.([]byte))
		om_array = append(om_array, kv_bytes)
	}
	return om_array
}

func (smt *SparseMerkleTree) EncodeRLP(w io.Writer) (err error) {

	var smtRaw []interface{}

	smtRaw = append(smtRaw, uint64(smt.depth))

	smtRaw = append(smtRaw, smt.root)

	var treeRaw []interface{}
	for level := range smt.tree {
		treeRaw = append(treeRaw, smt.serializeOrderedMapRaw(smt.tree[level]))
	}
	smtRaw = append(smtRaw, treeRaw)

	leavesRaw := smt.serializeOrderedMapRaw(smt.leaves)
	smtRaw = append(smtRaw, leavesRaw)

	var defaultNodesRaw []interface{}
	for level := range smt.defaultNodes {
		defaultNodesRaw = append(defaultNodesRaw, smt.defaultNodes[level])
	}
	smtRaw = append(smtRaw, defaultNodesRaw)

	return rlp.Encode(w, smtRaw)
}


func (smt *SparseMerkleTree) DecodeRLP(s *rlp.Stream) (err error) {

	s.List()
	if err != nil {
		return err
	}

	depth, err := s.Uint()
	if err != nil {
		return err
	}
	smt.depth = int64(depth)

	root, err := s.Bytes()
	if err != nil {
		return err
	}
	smt.root = root

		var tree []*ordered_map.OrderedMap
		size, err := s.List()

		if err != nil {
			return err
		}
		for size > 0 {
			omSize, om, err := smt.parseOrderedMapFromStream(s)
			if err != nil {
				if err.Error() == "rlp: end of list" {
					break
				}
				return nil
			}
			tree = append(tree, om)
			size -= omSize
		}
		s.ListEnd()
		smt.tree = tree

	_, leaves, err := smt.parseOrderedMapFromStream(s)
	smt.leaves = leaves
	defaultNodes, err := smt.parseList(s)

	if err != nil {
		return err
	}

	smt.defaultNodes = defaultNodes

	s.ListEnd()
	return nil
}


func (smt *SparseMerkleTree) parseOrderedMapFromStream(s *rlp.Stream) (uint64, *ordered_map.OrderedMap, error) {
	om := ordered_map.NewOrderedMap()
	sizeBefore, err := s.List()
	if err != nil {
		return 0, nil, err
	}

	size := sizeBefore
	for size > 0 {
		kvSize, key, value, err := smt.parseOrderedMapKeyValueFromStream(s)
		if err != nil {
			if err.Error() == "rlp: end of list" {
				break
			}
			return 0, nil, err
		}
		size -= kvSize
		om.Set(key, value)
	}

	s.ListEnd()
	return sizeBefore, om, err
}

func (smt *SparseMerkleTree) parseOrderedMapKeyValueFromStream(s *rlp.Stream) (uint64, int64, []byte, error) {
	size, err := s.List()
	if err != nil {
		return 0, 0, nil, err
	}
	key, err := s.Uint()
	if err != nil {
		return 0, 0, nil, err
	}
	value, err := s.Bytes()
	if err != nil {
		return 0, 0, nil, err
	}
	s.ListEnd()
	return size, int64(key), value, err
}


func (smt *SparseMerkleTree) parseList(s *rlp.Stream) ([][]byte, error) {
	var defaultNodes [][]byte
	_, err := s.List()
	if err != nil {
		return nil, err
	}

	for true {
		defaultNode, err := s.Bytes()
		if err != nil {
			if err.Error() == "rlp: end of list" {
				break
			}
			return nil, err
		}
		defaultNodes = append(defaultNodes, defaultNode)
	}

	s.ListEnd()
	return defaultNodes, err
}

func (smt *SparseMerkleTree) Serialize() ([]byte, error) {

	smtBytes, err := rlp.EncodeToBytes(smt)
	if err != nil {
		panic(err)
	}

	return smtBytes, nil

}

func LoadSparseMerkleTree(stmByte []byte) (*SparseMerkleTree, error) {
	var smt = &SparseMerkleTree{0, nil, nil, nil, nil ,}
	err := rlp.DecodeBytes(stmByte, &smt)
	if err != nil {
		return nil, err
	}
	return smt ,nil
}

func NewSparseMerkleTree(depth int64, leaves map[int64][]byte) (*SparseMerkleTree, error) {
	var err error = nil
	pow := float64(math.Pow(2, float64(depth-1)))
	if float64(len(leaves)) > pow {
		return nil, errors.New(fmt.Sprintf("tree with depth %d cannot have %d leaves", depth, len(leaves)))
	}

	var keys []int64
	for k := range leaves {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	sortedLeaves := ordered_map.NewOrderedMap()
	for _, k := range keys {
		sortedLeaves.Set(k, leaves[k])
	}

	smt := &SparseMerkleTree{depth, sortedLeaves, nil, nil, nil}
	smt.defaultNodes = smt.CreateDefaultNodes(smt.depth)

	if leaves != nil {
		smt.tree = smt.CreateTree(smt.leaves, smt.depth, smt.defaultNodes)
		root, ok := smt.tree[len(smt.tree)-1].Get(int64(0))
		if !ok {
			return nil, errors.New("root not found")
		}
		smt.root = root.([]byte)
	} else {
		smt.root = smt.defaultNodes[smt.depth-1]
	}

	return smt, err
}
