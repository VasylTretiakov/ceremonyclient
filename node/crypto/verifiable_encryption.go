package crypto

import (
	"encoding/binary"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
	generated "source.quilibrium.com/quilibrium/monorepo/verenc/generated/verenc"
)

type VerEnc interface {
	ToBytes() []byte
	GetStatement() []byte
	Verify(proof []byte) bool
}

type VerEncProof interface {
	ToBytes() []byte
	Compress() VerEnc
	Verify() bool
}

type VerifiableEncryptor interface {
	Encrypt(
		data []byte,
		publicKey []byte,
	) []VerEncProof
	Decrypt(
		encrypted []VerEnc,
		decryptionKey []byte,
	) []byte
}

var _ VerifiableEncryptor = (*MPCitHVerifiableEncryptor)(nil)

type MPCitHVerEncProof struct {
	generated.VerencProof
}

type MPCitHVerEnc struct {
	generated.CompressedCiphertext
	BlindingPubkey []uint8
	Statement      []uint8
}

func MPCitHVerEncProofFromBytes(data []byte) MPCitHVerEncProof {
	if len(data) != 9012 {
		return MPCitHVerEncProof{}
	}

	polycom := [][]byte{}
	for i := 0; i < 23; i++ {
		polycom = append(polycom, data[235+(i*57):292+(i*57)])
	}

	ctexts := []generated.VerencCiphertext{}
	srs := []generated.VerencShare{}

	for i := 0; i < 42; i++ {
		ctexts = append(ctexts, generated.VerencCiphertext{
			C1: data[1546+(i*(57+56+4)) : 1603+(i*(57+56+4))],
			C2: data[1603+(i*(57+56+4)) : 1659+(i*(57+56+4))],
			I:  binary.BigEndian.Uint64(data[1659+(i*(57+56+4)) : 1663+(i*(57+56+4))]),
		})
	}

	for i := 0; i < 22; i++ {
		srs = append(srs, generated.VerencShare{
			S1: data[6460+(i*(56+56+4)) : 6516+(i*(56+56+4))],
			S2: data[6516+(i*(56+56+4)) : 6572+(i*(56+56+4))],
			I:  binary.BigEndian.Uint64(data[6572+(i*(56+56+4)) : 6576+(i*(56+56+4))]),
		})
	}

	return MPCitHVerEncProof{
		generated.VerencProof{
			BlindingPubkey: data[:57],
			EncryptionKey:  data[57:114],
			Statement:      data[114:171],
			Challenge:      data[171:235],
			Polycom:        polycom,
			Ctexts:         ctexts,
			SharesRands:    srs,
		},
	}
}

func (p MPCitHVerEncProof) ToBytes() []byte {
	output := []byte{}
	output = append(output, p.BlindingPubkey...)
	output = append(output, p.EncryptionKey...)
	output = append(output, p.Statement...)
	output = append(output, p.Challenge...)

	for _, pol := range p.Polycom {
		output = append(output, pol...)
	}

	for _, ct := range p.Ctexts {
		output = append(output, ct.C1...)
		output = append(output, ct.C2...)
		output = binary.BigEndian.AppendUint64(output, ct.I)
	}

	for _, sr := range p.SharesRands {
		output = append(output, sr.S1...)
		output = append(output, sr.S2...)
		output = binary.BigEndian.AppendUint64(output, sr.I)
	}

	return output
}

func (p MPCitHVerEncProof) Compress() VerEnc {
	compressed := verenc.VerencCompress(p.VerencProof)
	return MPCitHVerEnc{
		CompressedCiphertext: compressed,
		BlindingPubkey:       p.BlindingPubkey,
		Statement:            p.Statement,
	}
}

func (p MPCitHVerEncProof) Verify() bool {
	return verenc.VerencVerify(p.VerencProof)
}

type InlineEnc struct {
	iv         []byte
	ciphertext []byte
}

func MPCitHVerEncFromBytes(data []byte) MPCitHVerEnc {
	ciphertext := generated.CompressedCiphertext{}
	for i := 0; i < 3; i++ {
		ciphertext.Ctexts = append(ciphertext.Ctexts, generated.VerencCiphertext{
			C1: data[0+(i*(57+56)) : 57+(i*(57+56))],
			C2: data[57+(i*(57+56)) : 113+(i*(57+56))],
		})
		ciphertext.Aux = append(ciphertext.Aux, data[507+(i*56):563+(i*56)])
	}
	return MPCitHVerEnc{
		CompressedCiphertext: ciphertext,
		BlindingPubkey:       data[731:788],
		Statement:            data[788:845],
	}
}

func (e MPCitHVerEnc) ToBytes() []byte {
	output := []byte{}
	for _, ct := range e.Ctexts {
		output = append(output, ct.C1...)
		output = append(output, ct.C2...)
	}
	for _, a := range e.Aux {
		output = append(output, a...)
	}
	output = append(output, e.BlindingPubkey...)
	output = append(output, e.Statement...)
	return output
}

func (e MPCitHVerEnc) GetStatement() []byte {
	return e.Statement
}

func (e MPCitHVerEnc) Verify(proof []byte) bool {
	proofData := MPCitHVerEncProofFromBytes(proof)
	return proofData.Verify()
}

type MPCitHVerifiableEncryptor struct {
	parallelism int
	lruCache    *lru.Cache[string, VerEnc]
}

func NewMPCitHVerifiableEncryptor(parallelism int) *MPCitHVerifiableEncryptor {
	cache, err := lru.New[string, VerEnc](10000)
	if err != nil {
		panic(err)
	}

	return &MPCitHVerifiableEncryptor{
		parallelism: parallelism,
		lruCache:    cache,
	}
}

func (v *MPCitHVerifiableEncryptor) Encrypt(
	data []byte,
	publicKey []byte,
) []VerEncProof {
	chunks := verenc.ChunkDataForVerenc(data)
	results := make([]VerEncProof, len(chunks))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range chunks {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk []byte, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			proof := verenc.NewVerencProofEncryptOnly(chunk, publicKey)
			results[i] = MPCitHVerEncProof{
				generated.VerencProof{
					BlindingPubkey: proof.BlindingPubkey,
					EncryptionKey:  proof.EncryptionKey,
					Statement:      proof.Statement,
					Challenge:      proof.Challenge,
					Polycom:        proof.Polycom,
					Ctexts:         proof.Ctexts,
					SharesRands:    proof.SharesRands,
				},
			}
		}(chunk, i)
	}
	wg.Wait()
	return results
}

func (v *MPCitHVerifiableEncryptor) EncryptAndCompress(
	data []byte,
	publicKey []byte,
) []VerEnc {
	chunks := verenc.ChunkDataForVerenc(data)
	results := make([]VerEnc, len(chunks))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range chunks {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk []byte, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			existing, ok := v.lruCache.Get(string(publicKey) + string(chunk))
			if ok {
				results[i] = existing
			} else {
				proof := verenc.NewVerencProofEncryptOnly(chunk, publicKey)
				result := MPCitHVerEncProof{
					generated.VerencProof{
						BlindingPubkey: proof.BlindingPubkey,
						EncryptionKey:  proof.EncryptionKey,
						Statement:      proof.Statement,
						Challenge:      proof.Challenge,
						Polycom:        proof.Polycom,
						Ctexts:         proof.Ctexts,
						SharesRands:    proof.SharesRands,
					},
				}
				results[i] = result.Compress()
				v.lruCache.Add(string(publicKey)+string(chunk), results[i])
			}
		}(chunk, i)
	}
	wg.Wait()
	return results
}

func (v *MPCitHVerifiableEncryptor) Decrypt(
	encrypted []VerEnc,
	decyptionKey []byte,
) []byte {
	results := make([][]byte, len(encrypted))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range encrypted {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk VerEnc, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			results[i] = verenc.VerencRecover(generated.VerencDecrypt{
				BlindingPubkey: chunk.(MPCitHVerEnc).BlindingPubkey,
				DecryptionKey:  decyptionKey,
				Statement:      chunk.(MPCitHVerEnc).Statement,
				Ciphertexts:    chunk.(MPCitHVerEnc).CompressedCiphertext,
			})
		}(chunk, i)
	}
	wg.Wait()
	return verenc.CombineChunkedData(results)
}
