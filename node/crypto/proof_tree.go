package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"math/big"

	rbls48581 "source.quilibrium.com/quilibrium/monorepo/bls48581"
)

func init() {
	gob.Register(&VectorCommitmentLeafNode{})
	gob.Register(&VectorCommitmentBranchNode{})
}

const (
	BranchNodes = 64
	BranchBits  = 6 // log2(64)
	BranchMask  = BranchNodes - 1
)

type VectorCommitmentNode interface {
	Commit(recalculate bool) []byte
	GetSize() *big.Int
}

type VectorCommitmentLeafNode struct {
	Key        []byte
	Value      []byte
	HashTarget []byte
	Commitment []byte
	Size       *big.Int
}

type VectorCommitmentBranchNode struct {
	Prefix        []int
	Children      [BranchNodes]VectorCommitmentNode
	Commitment    []byte
	Size          *big.Int
	LeafCount     int
	LongestBranch int
}

func (n *VectorCommitmentLeafNode) Commit(recalculate bool) []byte {
	if n.Commitment == nil || recalculate {
		h := sha512.New()
		h.Write([]byte{0})
		h.Write(n.Key)
		if len(n.HashTarget) != 0 {
			h.Write(n.HashTarget)
		} else {
			h.Write(n.Value)
		}
		n.Commitment = h.Sum(nil)
	}
	return n.Commitment
}

func (n *VectorCommitmentLeafNode) GetSize() *big.Int {
	return n.Size
}

func (n *VectorCommitmentBranchNode) Commit(recalculate bool) []byte {
	if n.Commitment == nil || recalculate {
		data := []byte{}
		for _, child := range n.Children {
			if child != nil {
				out := child.Commit(recalculate)
				switch c := child.(type) {
				case *VectorCommitmentBranchNode:
					h := sha512.New()
					h.Write([]byte{1})
					for _, p := range c.Prefix {
						h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
					}
					h.Write(out)
					out = h.Sum(nil)
				case *VectorCommitmentLeafNode:
					// do nothing
				}
				data = append(data, out...)
			} else {
				data = append(data, make([]byte, 64)...)
			}
		}

		n.Commitment = rbls48581.CommitRaw(data, 64)
	}

	return n.Commitment
}

func (n *VectorCommitmentBranchNode) Verify(index int, proof []byte) bool {
	data := []byte{}
	if n.Commitment == nil {
		for _, child := range n.Children {
			if child != nil {
				out := child.Commit(false)
				switch c := child.(type) {
				case *VectorCommitmentBranchNode:
					h := sha512.New()
					h.Write([]byte{1})
					for _, p := range c.Prefix {
						h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
					}
					h.Write(out)
					out = h.Sum(nil)
				case *VectorCommitmentLeafNode:
					// do nothing
				}
				data = append(data, out...)
			} else {
				data = append(data, make([]byte, 64)...)
			}
		}

		n.Commitment = rbls48581.CommitRaw(data, 64)
		data = data[64*index : 64*(index+1)]
	} else {
		child := n.Children[index]
		if child != nil {
			out := child.Commit(false)
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return rbls48581.VerifyRaw(data, n.Commitment, uint64(index), proof, 64)
}

func (n *VectorCommitmentBranchNode) GetSize() *big.Int {
	return n.Size
}

func (n *VectorCommitmentBranchNode) Prove(index int) []byte {
	data := []byte{}
	for _, child := range n.Children {
		if child != nil {
			out := child.Commit(false)
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return rbls48581.ProveRaw(data, uint64(index), 64)
}

type VectorCommitmentTree struct {
	Root VectorCommitmentNode
}

// getNextNibble returns the next BranchBits bits from the key starting at pos
func getNextNibble(key []byte, pos int) int {
	startByte := pos / 8
	if startByte >= len(key) {
		return 0
	}

	// Calculate how many bits we need from the current byte
	startBit := pos % 8
	bitsFromCurrentByte := 8 - startBit

	result := int(key[startByte] & ((1 << bitsFromCurrentByte) - 1))

	if bitsFromCurrentByte >= BranchBits {
		// We have enough bits in the current byte
		return (result >> (bitsFromCurrentByte - BranchBits)) & BranchMask
	}

	// We need bits from the next byte
	result = result << (BranchBits - bitsFromCurrentByte)
	if startByte+1 < len(key) {
		remainingBits := BranchBits - bitsFromCurrentByte
		nextByte := int(key[startByte+1])
		result |= (nextByte >> (8 - remainingBits))
	}

	return result & BranchMask
}

func getNibblesUntilDiverge(key1, key2 []byte, startDepth int) ([]int, int) {
	var nibbles []int
	depth := startDepth

	for {
		n1 := getNextNibble(key1, depth)
		n2 := getNextNibble(key2, depth)
		if n1 != n2 {
			return nibbles, depth
		}
		nibbles = append(nibbles, n1)
		depth += BranchBits
	}
}

func recalcMetadata(node VectorCommitmentNode) (
	leafCount int,
	longestBranch int,
	size *big.Int,
) {
	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		// A leaf counts as one, and its depth (from itself) is zero.
		return 1, 0, n.Size
	case *VectorCommitmentBranchNode:
		totalLeaves := 0
		maxChildDepth := 0
		size := new(big.Int)
		for _, child := range n.Children {
			if child != nil {
				cLeaves, cDepth, cSize := recalcMetadata(child)
				totalLeaves += cLeaves
				size.Add(size, cSize)
				if cDepth > maxChildDepth {
					maxChildDepth = cDepth
				}
			}
		}
		// Store the aggregated values in the branch node.
		n.LeafCount = totalLeaves
		// The branch’s longest branch is one more than its deepest child.
		n.LongestBranch = maxChildDepth + 1
		n.Size = size
		return totalLeaves, n.LongestBranch, n.Size
	}
	return 0, 0, new(big.Int)
}

// Insert adds or updates a key-value pair in the tree
func (t *VectorCommitmentTree) Insert(
	key, value, hashTarget []byte,
	size *big.Int,
) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var insert func(node VectorCommitmentNode, depth int) VectorCommitmentNode
	insert = func(node VectorCommitmentNode, depth int) VectorCommitmentNode {
		if node == nil {
			return &VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = value
				n.HashTarget = hashTarget
				n.Commitment = nil
				n.Size = size
				return n
			}

			// Get common prefix nibbles and divergence point
			sharedNibbles, divergeDepth := getNibblesUntilDiverge(n.Key, key, depth)

			// Create single branch node with shared prefix
			branch := &VectorCommitmentBranchNode{
				Prefix: sharedNibbles,
			}

			// Add both leaves at their final positions
			finalOldNibble := getNextNibble(n.Key, divergeDepth)
			finalNewNibble := getNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}

			return branch

		case *VectorCommitmentBranchNode:
			if len(n.Prefix) > 0 {
				// Check if the new key matches the prefix
				for i, expectedNibble := range n.Prefix {
					actualNibble := getNextNibble(key, depth+i*BranchBits)
					if actualNibble != expectedNibble {
						// Create new branch with shared prefix subset
						newBranch := &VectorCommitmentBranchNode{
							Prefix: n.Prefix[:i],
						}
						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &VectorCommitmentLeafNode{
							Key:        key,
							Value:      value,
							HashTarget: hashTarget,
							Size:       size,
						}
						recalcMetadata(newBranch)
						return newBranch
					}
				}

				// Key matches prefix, continue with final nibble
				finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
				n.Children[finalNibble] = insert(
					n.Children[finalNibble],
					depth+len(n.Prefix)*BranchBits+BranchBits,
				)
				n.Commitment = nil
				recalcMetadata(n)
				return n
			} else {
				// Simple branch without prefix
				nibble := getNextNibble(key, depth)
				n.Children[nibble] = insert(n.Children[nibble], depth+BranchBits)
				n.Commitment = nil
				recalcMetadata(n)
				return n
			}
		}

		return nil
	}

	t.Root = insert(t.Root, 0)
	return nil
}

func (t *VectorCommitmentTree) Verify(key []byte, proofs [][]byte) bool {
	if len(key) == 0 {
		return false
	}

	var verify func(node VectorCommitmentNode, proofs [][]byte, depth int) bool
	verify = func(node VectorCommitmentNode, proofs [][]byte, depth int) bool {
		if node == nil {
			return false
		}

		if len(proofs) == 0 {
			return false
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return bytes.Equal(n.Value, proofs[0])
			}
			return false

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return false
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			if !n.Verify(finalNibble, proofs[0]) {
				return false
			}

			return verify(n.Children[finalNibble], proofs[1:], depth+len(n.Prefix)*BranchBits+BranchBits)
		}

		return false
	}

	return verify(t.Root, proofs, 0)
}

func (t *VectorCommitmentTree) Prove(key []byte) [][]byte {
	if len(key) == 0 {
		return nil
	}

	var prove func(node VectorCommitmentNode, depth int) [][]byte
	prove = func(node VectorCommitmentNode, depth int) [][]byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return [][]byte{n.Value}
			}
			return nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			proofs := [][]byte{n.Prove(finalNibble)}

			return append(proofs, prove(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)...)
		}

		return nil
	}

	return prove(t.Root, 0)
}

// Get retrieves a value from the tree by key
func (t *VectorCommitmentTree) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key not allowed")
	}

	var get func(node VectorCommitmentNode, depth int) []byte
	get = func(node VectorCommitmentNode, depth int) []byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return n.Value
			}
			return nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}
			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			return get(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)
		}

		return nil
	}

	value := get(t.Root, 0)
	if value == nil {
		return nil, errors.New("key not found")
	}
	return value, nil
}

// Delete removes a key-value pair from the tree
func (t *VectorCommitmentTree) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var remove func(node VectorCommitmentNode, depth int) VectorCommitmentNode
	remove = func(node VectorCommitmentNode, depth int) VectorCommitmentNode {
		if node == nil {
			return nil
		}

		switch n := node.(type) {

		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return nil
			}
			return n

		case *VectorCommitmentBranchNode:
			for i, expectedNibble := range n.Prefix {
				currentNibble := getNextNibble(key, depth+i*BranchBits)
				if currentNibble != expectedNibble {
					return n
				}
			}

			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			n.Children[finalNibble] =
				remove(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)

			n.Commitment = nil

			childCount := 0
			var lastChild VectorCommitmentNode
			var lastChildIndex int
			for i, child := range n.Children {
				if child != nil {
					childCount++
					lastChild = child
					lastChildIndex = i
				}
			}

			var retNode VectorCommitmentNode
			switch childCount {
			case 0:
				retNode = nil
			case 1:
				if childBranch, ok := lastChild.(*VectorCommitmentBranchNode); ok {
					// Merge:
					//   n.Prefix + [lastChildIndex] + childBranch.Prefix
					mergedPrefix := make([]int, 0, len(n.Prefix)+1+len(childBranch.Prefix))
					mergedPrefix = append(mergedPrefix, n.Prefix...)
					mergedPrefix = append(mergedPrefix, lastChildIndex)
					mergedPrefix = append(mergedPrefix, childBranch.Prefix...)

					childBranch.Prefix = mergedPrefix
					childBranch.Commitment = nil
					retNode = childBranch
				} else {
					retNode = lastChild
				}
			default:
				retNode = n
			}

			if branch, ok := retNode.(*VectorCommitmentBranchNode); ok {
				recalcMetadata(branch)
			}

			return retNode
		default:
			return node
		}
	}

	t.Root = remove(t.Root, 0)
	return nil
}

func (t *VectorCommitmentTree) GetMetadata() (leafCount int, longestBranch int) {
	switch root := t.Root.(type) {
	case nil:
		return 0, 0
	case *VectorCommitmentLeafNode:
		return 1, 0
	case *VectorCommitmentBranchNode:
		return root.LeafCount, root.LongestBranch
	}
	return 0, 0
}

// Commit returns the root of the tree
func (t *VectorCommitmentTree) Commit(recalculate bool) []byte {
	if t.Root == nil {
		return make([]byte, 64)
	}
	return t.Root.Commit(recalculate)
}

func (t *VectorCommitmentTree) GetSize() *big.Int {
	return t.Root.GetSize()
}

func DebugNode(node VectorCommitmentNode, depth int, prefix string) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		fmt.Printf("%sLeaf: key=%x value=%x\n", prefix, n.Key, n.Value)
	case *VectorCommitmentBranchNode:
		fmt.Printf("%sBranch %v:\n", prefix, n.Prefix)
		for i, child := range n.Children {
			if child != nil {
				fmt.Printf("%s  [%d]:\n", prefix, i)
				DebugNode(child, depth+1, prefix+"    ")
			}
		}
	}
}
