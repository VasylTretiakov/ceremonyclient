package crypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/bls48581/generated/bls48581"
)

func BenchmarkVectorCommitmentTreeInsert(b *testing.B) {
	tree := &VectorCommitmentTree{}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, d)
		err := tree.Insert(d, d)
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
	}
}

func BenchmarkVectorCommitmentTreeCommit(b *testing.B) {
	tree := &VectorCommitmentTree{}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, d)
		err := tree.Insert(d, d)
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		tree.Commit()
	}
}

func BenchmarkVectorCommitmentTreeProve(b *testing.B) {
	tree := &VectorCommitmentTree{}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, d)
		err := tree.Insert(d, d)
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		tree.Prove(d)
	}
}

func BenchmarkVectorCommitmentTreeVerify(b *testing.B) {
	tree := &VectorCommitmentTree{}
	addresses := [][]byte{}

	for i := range b.N {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, d)
		err := tree.Insert(d, d)
		if err != nil {
			b.Errorf("Failed to insert item %d: %v", i, err)
		}
		p := tree.Prove(d)
		if !tree.Verify(d, p) {
			b.Errorf("bad proof")
		}
	}
}

func TestVectorCommitmentTrees(t *testing.T) {
	bls48581.Init()
	tree := &VectorCommitmentTree{}

	// Test single insert
	err := tree.Insert([]byte("key1"), []byte("value1"))
	if err != nil {
		t.Errorf("Failed to insert: %v", err)
	}

	// Test duplicate key
	err = tree.Insert([]byte("key1"), []byte("value2"))
	if err != nil {
		t.Errorf("Failed to update existing key: %v", err)
	}

	value, err := tree.Get([]byte("key1"))
	if err != nil {
		t.Errorf("Failed to get value: %v", err)
	}
	if !bytes.Equal(value, []byte("value2")) {
		t.Errorf("Expected value2, got %s", string(value))
	}

	// Test empty key
	err = tree.Insert([]byte{}, []byte("value"))
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	tree = &VectorCommitmentTree{}

	// Test get on empty tree
	_, err = tree.Get([]byte("nonexistent"))
	if err == nil {
		t.Error("Expected error for nonexistent key, got none")
	}

	// Insert and get
	tree.Insert([]byte("key1"), []byte("value1"))
	value, err = tree.Get([]byte("key1"))
	if err != nil {
		t.Errorf("Failed to get value: %v", err)
	}
	if !bytes.Equal(value, []byte("value1")) {
		t.Errorf("Expected value1, got %s", string(value))
	}

	// Test empty key
	_, err = tree.Get([]byte{})
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	tree = &VectorCommitmentTree{}

	// Test delete on empty tree
	err = tree.Delete([]byte("nonexistent"))
	if err != nil {
		t.Errorf("Delete on empty tree should not return error: %v", err)
	}

	// Insert and delete
	tree.Insert([]byte("key1"), []byte("value1"))
	err = tree.Delete([]byte("key1"))
	if err != nil {
		t.Errorf("Failed to delete: %v", err)
	}

	// Verify deletion
	_, err = tree.Get([]byte("key1"))
	if err == nil {
		t.Error("Expected error for deleted key, got none")
	}

	// Test empty key
	err = tree.Delete([]byte{})
	if err == nil {
		t.Error("Expected error for empty key, got none")
	}

	tree = &VectorCommitmentTree{}

	// Insert keys that share common prefix
	keys := []string{
		"key1",
		"key2",
		"key3",
		"completely_different",
	}

	for i, key := range keys {
		err := tree.Insert([]byte(key), []byte("value"+string(rune('1'+i))))
		if err != nil {
			t.Errorf("Failed to insert key %s: %v", key, err)
		}
	}

	// Verify all values
	for i, key := range keys {
		value, err := tree.Get([]byte(key))
		if err != nil {
			t.Errorf("Failed to get key %s: %v", key, err)
		}
		expected := []byte("value" + string(rune('1'+i)))
		if !bytes.Equal(value, expected) {
			t.Errorf("Expected %s, got %s", string(expected), string(value))
		}
	}

	// Delete middle key
	err = tree.Delete([]byte("key2"))
	if err != nil {
		t.Errorf("Failed to delete key2: %v", err)
	}

	// Verify key2 is gone but others remain
	_, err = tree.Get([]byte("key2"))
	if err == nil {
		t.Error("Expected error for deleted key2, got none")
	}

	// Check remaining keys
	remainingKeys := []string{"key1", "key3", "completely_different"}
	remainingValues := []string{"value1", "value3", "value4"}
	for i, key := range remainingKeys {
		value, err := tree.Get([]byte(key))
		if err != nil {
			t.Errorf("Failed to get key %s after deletion: %v", key, err)
		}
		expected := []byte(remainingValues[i])
		if !bytes.Equal(value, expected) {
			t.Errorf("Expected %s, got %s", string(expected), string(value))
		}
	}

	tree = &VectorCommitmentTree{}

	// Empty tree should be empty
	emptyRoot := tree.Root
	if emptyRoot != nil {
		t.Errorf("Expected empty root")
	}

	// Root should change after insert
	tree.Insert([]byte("key1"), []byte("value1"))
	firstRoot := tree.Root.Commit()

	if bytes.Equal(firstRoot, bytes.Repeat([]byte{0x00}, 64)) {
		t.Error("Root hash should change after insert")
	}

	// Root should change after update
	tree.Insert([]byte("key1"), []byte("value2"))
	secondRoot := tree.Root.Commit()

	if bytes.Equal(secondRoot, firstRoot) {
		t.Error("Root hash should change after update")
	}

	// Root should change after delete
	tree.Delete([]byte("key1"))
	thirdRoot := tree.Root

	if thirdRoot != nil {
		t.Error("Root hash should match empty tree after deleting all entries")
	}

	tree = &VectorCommitmentTree{}
	cmptree := &VectorCommitmentTree{}

	addresses := [][]byte{}

	for i := 0; i < 1000; i++ {
		d := make([]byte, 32)
		rand.Read(d)
		addresses = append(addresses, d)
	}

	// Insert 1000 items
	for i := 0; i < 1000; i++ {
		key := addresses[i]
		value := addresses[i]
		err := tree.Insert(key, value)
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Insert 1000 items in reverse
	for i := 999; i >= 0; i-- {
		key := addresses[i]
		value := addresses[i]
		err := cmptree.Insert(key, value)
		if err != nil {
			t.Errorf("Failed to insert item %d: %v", i, err)
		}
	}

	// Verify all items
	for i := 0; i < 1000; i++ {
		key := addresses[i]
		expected := addresses[i]
		value, err := tree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		cmpvalue, err := cmptree.Get(key)
		if err != nil {
			t.Errorf("Failed to get item %d: %v", i, err)
		}
		if !bytes.Equal(value, expected) {
			t.Errorf("Item %d: expected %x, got %x", i, string(expected), string(value))
		}
		if !bytes.Equal(value, cmpvalue) {
			t.Errorf("Item %d: expected %x, got %x", i, string(value), string(cmpvalue))
		}
	}

	tcommit := tree.Root.Commit()
	cmptcommit := cmptree.Root.Commit()

	if !bytes.Equal(tcommit, cmptcommit) {
		t.Errorf("tree mismatch, %x, %x", tcommit, cmptcommit)
	}

	proofs := tree.Prove(addresses[500])
	if !tree.Verify(addresses[500], proofs) {
		t.Errorf("proof failed")
	}

	for _, p := range proofs {
		fmt.Printf("%x\n", p)
	}
}
