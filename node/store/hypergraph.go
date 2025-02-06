package store

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
)

type HypergraphStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	LoadHypergraph() (
		*application.Hypergraph,
		error,
	)
	SaveHypergraph(
		txn Transaction,
		hg *application.Hypergraph,
	) error
}

var _ HypergraphStore = (*PebbleHypergraphStore)(nil)

type PebbleHypergraphStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleHypergraphStore(
	db KVDB,
	logger *zap.Logger,
) *PebbleHypergraphStore {
	return &PebbleHypergraphStore{
		db,
		logger,
	}
}

const (
	HYPERGRAPH_SHARD  = 0x09
	VERTEX_ADDS       = 0x00
	VERTEX_REMOVES    = 0x10
	HYPEREDGE_ADDS    = 0x01
	HYPEREDGE_REMOVES = 0x11
)

func hypergraphVertexAddsKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexRemovesKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeAddsKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeRemovesKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func shardKeyFromKey(key []byte) application.ShardKey {
	return application.ShardKey{
		L1: [3]byte(key[2:5]),
		L2: [32]byte(key[5:]),
	}
}

func (p *PebbleHypergraphStore) NewTransaction(indexed bool) (
	Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleHypergraphStore) LoadHypergraph() (
	*application.Hypergraph,
	error,
) {
	hg := application.NewHypergraph()
	vertexAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS},
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexAddsIter.Close()
	for vertexAddsIter.First(); vertexAddsIter.Valid(); vertexAddsIter.Next() {
		shardKey := make([]byte, len(vertexAddsIter.Key()))
		copy(shardKey, vertexAddsIter.Key())

		err := hg.ImportFromBytes(
			application.VertexAtomType,
			application.AddsPhaseType,
			shardKeyFromKey(shardKey),
			vertexAddsIter.Value(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	vertexRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES},
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES + 1},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexRemovesIter.Close()
	for vertexRemovesIter.First(); vertexRemovesIter.Valid(); vertexRemovesIter.Next() {
		shardKey := make([]byte, len(vertexRemovesIter.Key()))
		copy(shardKey, vertexRemovesIter.Key())

		err := hg.ImportFromBytes(
			application.VertexAtomType,
			application.RemovesPhaseType,
			shardKeyFromKey(shardKey),
			vertexRemovesIter.Value(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeAddsIter.Close()
	for hyperedgeAddsIter.First(); hyperedgeAddsIter.Valid(); hyperedgeAddsIter.Next() {
		shardKey := make([]byte, len(hyperedgeAddsIter.Key()))
		copy(shardKey, hyperedgeAddsIter.Key())

		err := hg.ImportFromBytes(
			application.HyperedgeAtomType,
			application.AddsPhaseType,
			shardKeyFromKey(shardKey),
			hyperedgeAddsIter.Value(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES + 1},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeRemovesIter.Close()
	for hyperedgeRemovesIter.First(); hyperedgeRemovesIter.Valid(); hyperedgeRemovesIter.Next() {
		shardKey := make([]byte, len(hyperedgeRemovesIter.Key()))
		copy(shardKey, hyperedgeRemovesIter.Key())

		err := hg.ImportFromBytes(
			application.HyperedgeAtomType,
			application.RemovesPhaseType,
			shardKeyFromKey(shardKey),
			hyperedgeRemovesIter.Value(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	return hg, nil
}

func (p *PebbleHypergraphStore) SaveHypergraph(
	txn Transaction,
	hg *application.Hypergraph,
) error {
	for shardKey, vertexAdds := range hg.GetVertexAdds() {
		if vertexAdds.IsDirty() {
			err := txn.Set(hypergraphVertexAddsKey(shardKey), vertexAdds.ToBytes())
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, vertexRemoves := range hg.GetVertexRemoves() {
		if vertexRemoves.IsDirty() {
			err := txn.Set(
				hypergraphVertexRemovesKey(shardKey),
				vertexRemoves.ToBytes(),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeAdds := range hg.GetHyperedgeAdds() {
		if hyperedgeAdds.IsDirty() {
			err := txn.Set(
				hypergraphHyperedgeAddsKey(shardKey),
				hyperedgeAdds.ToBytes(),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeRemoves := range hg.GetHyperedgeRemoves() {
		if hyperedgeRemoves.IsDirty() {
			err := txn.Set(
				hypergraphHyperedgeRemovesKey(shardKey),
				hyperedgeRemoves.ToBytes(),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	return nil
}
