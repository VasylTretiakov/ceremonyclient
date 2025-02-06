package verenc_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"source.quilibrium.com/quilibrium/monorepo/verenc"
	generated "source.quilibrium.com/quilibrium/monorepo/verenc/generated/verenc"
)

func TestVerenc(t *testing.T) {
	data := make([]byte, 56)
	copy(data[1:6], []byte("hello"))
	proof := verenc.NewVerencProof(data)
	if !verenc.VerencVerify(generated.VerencProof{
		BlindingPubkey: proof.BlindingPubkey,
		EncryptionKey:  proof.EncryptionKey,
		Statement:      proof.Statement,
		Challenge:      proof.Challenge,
		Polycom:        proof.Polycom,
		Ctexts:         proof.Ctexts,
		SharesRands:    proof.SharesRands,
	}) {
		t.FailNow()
	}
	compressed := verenc.VerencCompress(generated.VerencProof{
		BlindingPubkey: proof.BlindingPubkey,
		EncryptionKey:  proof.EncryptionKey,
		Statement:      proof.Statement,
		Challenge:      proof.Challenge,
		Polycom:        proof.Polycom,
		Ctexts:         proof.Ctexts,
		SharesRands:    proof.SharesRands,
	})
	recovered := verenc.VerencRecover(generated.VerencDecrypt{
		BlindingPubkey: proof.BlindingPubkey,
		Statement:      proof.Statement,
		DecryptionKey:  proof.DecryptionKey,
		Ciphertexts:    compressed,
	})
	if !bytes.Equal(data, recovered) {
		t.FailNow()
	}
}

func TestDataChunking(t *testing.T) {
	data := make([]byte, 1300)
	rand.Read(data)
	chunks := verenc.ChunkDataForVerenc(data)
	result := verenc.CombineChunkedData(chunks)
	if !bytes.Equal(data, result[:1300]) {
		t.FailNow()
	}
}

func TestVerencWithChunking(t *testing.T) {
	data := make([]byte, 1300)
	rand.Read(data)
	chunks := verenc.ChunkDataForVerenc(data)
	results := [][]byte{}
	for i, chunk := range chunks {
		proof := verenc.NewVerencProof(chunk)
		if !verenc.VerencVerify(generated.VerencProof{
			BlindingPubkey: proof.BlindingPubkey,
			EncryptionKey:  proof.EncryptionKey,
			Statement:      proof.Statement,
			Challenge:      proof.Challenge,
			Polycom:        proof.Polycom,
			Ctexts:         proof.Ctexts,
			SharesRands:    proof.SharesRands,
		}) {
			t.FailNow()
		}
		compressed := verenc.VerencCompress(generated.VerencProof{
			BlindingPubkey: proof.BlindingPubkey,
			EncryptionKey:  proof.EncryptionKey,
			Statement:      proof.Statement,
			Challenge:      proof.Challenge,
			Polycom:        proof.Polycom,
			Ctexts:         proof.Ctexts,
			SharesRands:    proof.SharesRands,
		})
		recovered := verenc.VerencRecover(generated.VerencDecrypt{
			BlindingPubkey: proof.BlindingPubkey,
			Statement:      proof.Statement,
			DecryptionKey:  proof.DecryptionKey,
			Ciphertexts:    compressed,
		})
		if !bytes.Equal(chunk, recovered) {
			fmt.Printf("recovered did not equal chunk %d: %x, %x\n", i, recovered, chunk)
			t.FailNow()
		}
		results = append(results, recovered)
	}
	result := verenc.CombineChunkedData(results)
	if !bytes.Equal(data, result[:1300]) {
		fmt.Printf("result did not equal original data, %x, %x\n", result[:1300], data)
		t.FailNow()
	}
}
