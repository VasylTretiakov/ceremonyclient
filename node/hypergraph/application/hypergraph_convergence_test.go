package application_test

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
)

type Operation struct {
	Type      string // "AddVertex", "RemoveVertex", "AddHyperedge", "RemoveHyperedge"
	Vertex    application.Vertex
	Hyperedge application.Hyperedge
}

func TestConvergence(t *testing.T) {
	numParties := 4
	numOperations := 100000
	enc := crypto.NewMPCitHVerifiableEncryptor(1)
	pub, _, _ := ed448.GenerateKey(crand.Reader)
	enc.Encrypt(make([]byte, 20), pub)
	vertices := make([]application.Vertex, numOperations)
	for i := 0; i < numOperations; i++ {
		vertices[i] = application.NewVertex(
			[32]byte{byte((i >> 8) % 256), byte((i % 256))},
			[32]byte{byte((i >> 8) / 256), byte(i / 256)},
			[]application.Encrypted{},
		)
	}

	hyperedges := make([]application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = application.NewHyperedge(
			[32]byte{0, 0, byte((i >> 8) % 256), byte(i % 256)},
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			v := vertices[rand.Intn(len(vertices))]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
		case 1:
			operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
		}
	}
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations2[i] = Operation{Type: "AddHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		case 1:
			operations2[i] = Operation{Type: "RemoveHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		}
	}

	crdts := make([]*application.Hypergraph, numParties)
	for i := 0; i < numParties; i++ {
		crdts[i] = application.NewHypergraph()
	}

	for i := 0; i < numParties; i++ {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(operations1), func(i, j int) { operations1[i], operations1[j] = operations1[j], operations1[i] })
		rand.Shuffle(len(operations2), func(i, j int) { operations2[i], operations2[j] = operations2[j], operations2[i] })

		for _, op := range operations1 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(op.Hyperedge)
			}
		}
		for _, op := range operations2 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(op.Vertex)
			case "AddHyperedge":
				fmt.Println("add", i, op)
				crdts[i].AddHyperedge(op.Hyperedge)
			case "RemoveHyperedge":
				fmt.Println("remove", i, op)
				crdts[i].RemoveHyperedge(op.Hyperedge)
			}
		}
	}

	crdts[0].GetSize()

	for _, v := range vertices {
		state := crdts[0].LookupVertex(v)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupVertex(v) != state {
				t.Errorf("Vertex %v has different state in CRDT %d", v, i)
			}
		}
	}
	for _, h := range hyperedges {
		state := crdts[0].LookupHyperedge(h)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupHyperedge(h) != state {
				t.Errorf("Hyperedge %v has different state in CRDT %d, %v", h, i, state)
			}
		}
	}
}
