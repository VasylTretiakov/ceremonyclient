package application

import (
	"bytes"
	"crypto/sha512"
	"encoding/gob"
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

type AtomType string
type PhaseType string

const (
	VertexAtomType    AtomType  = "vertex"
	HyperedgeAtomType AtomType  = "hyperedge"
	AddsPhaseType     PhaseType = "adds"
	RemovesPhaseType  PhaseType = "removes"
)

type Location [64]byte // 32 bytes for AppAddress + 32 bytes for DataAddress

var ErrInvalidAtomType = errors.New("invalid atom type for set")
var ErrInvalidLocation = errors.New("invalid location")
var ErrMissingExtrinsics = errors.New("missing extrinsics")
var ErrIsExtrinsic = errors.New("is extrinsic")

// Extract only needed methods of VEnc interface
type Encrypted interface {
	ToBytes() []byte
	GetStatement() []byte
	Verify(proof []byte) bool
}

type Vertex interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	ToBytes() []byte
	GetData() []Encrypted
	GetSize() *big.Int
	Commit() []byte
}

type Hyperedge interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	ToBytes() []byte
	AddExtrinsic(a Atom)
	RemoveExtrinsic(a Atom)
	GetExtrinsics() map[[64]byte]Atom
	GetSize() *big.Int
	Commit() []byte
}

type vertex struct {
	appAddress  [32]byte
	dataAddress [32]byte
	data        []Encrypted
	dataTree    *crypto.VectorCommitmentTree
}

type hyperedge struct {
	appAddress  [32]byte
	dataAddress [32]byte
	extrinsics  map[[64]byte]Atom
	extTree     *crypto.VectorCommitmentTree
}

var _ Vertex = (*vertex)(nil)
var _ Hyperedge = (*hyperedge)(nil)

type Atom interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	GetSize() *big.Int
	ToBytes() []byte
	Commit() []byte
}

func atomFromBytes(data []byte) Atom {
	tree := &crypto.VectorCommitmentTree{}
	var b bytes.Buffer
	b.Write(data[65:])
	dec := gob.NewDecoder(&b)
	if err := dec.Decode(tree); err != nil {
		return nil
	}

	if data[0] == 0x00 {
		encData := []Encrypted{}
		for _, d := range crypto.GetAllLeaves(tree) {
			verencData := crypto.MPCitHVerEncFromBytes(d.Value)
			encData = append(encData, verencData)
		}
		return &vertex{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			data:        encData,
			dataTree:    tree,
		}
	} else {
		extrinsics := make(map[[64]byte]Atom)
		for _, a := range crypto.GetAllLeaves(tree) {
			atom := atomFromBytes(a.Value)
			extrinsics[[64]byte(a.Key)] = atom
		}
		return &hyperedge{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			extrinsics:  extrinsics,
			extTree:     tree,
		}
	}
}

func NewVertex(
	appAddress [32]byte,
	dataAddress [32]byte,
	data []Encrypted,
) Vertex {
	dataTree := &crypto.VectorCommitmentTree{}
	for _, d := range data {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
	}
	return &vertex{
		appAddress,
		dataAddress,
		data,
		dataTree,
	}
}

func NewHyperedge(
	appAddress [32]byte,
	dataAddress [32]byte,
) Hyperedge {
	return &hyperedge{
		appAddress:  appAddress,
		dataAddress: dataAddress,
		extrinsics:  make(map[[64]byte]Atom),
		extTree:     &crypto.VectorCommitmentTree{},
	}
}

func (v *vertex) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], v.appAddress[:])
	copy(id[32:64], v.dataAddress[:])
	return id
}

func (v *vertex) GetSize() *big.Int {
	return big.NewInt(int64(len(v.data) * 54))
}

func (v *vertex) GetAtomType() AtomType {
	return VertexAtomType
}

func (v *vertex) GetLocation() Location {
	var loc Location
	copy(loc[:32], v.appAddress[:])
	copy(loc[32:], v.dataAddress[:])
	return loc
}

func (v *vertex) GetAppAddress() [32]byte {
	return v.appAddress
}

func (v *vertex) GetDataAddress() [32]byte {
	return v.dataAddress
}

func (v *vertex) GetData() []Encrypted {
	return v.data
}

func (v *vertex) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v.dataTree); err != nil {
		return nil
	}
	return append(
		append(
			append(
				[]byte{0x00},
				v.appAddress[:]...,
			),
			v.dataAddress[:]...,
		),
		buf.Bytes()...,
	)
}

func (v *vertex) Commit() []byte {
	return v.dataTree.Commit(false)
}

func (h *hyperedge) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], h.appAddress[:])
	copy(id[32:], h.dataAddress[:])
	return id
}

func (h *hyperedge) GetSize() *big.Int {
	return big.NewInt(int64(len(h.extrinsics)))
}

func (h *hyperedge) GetAtomType() AtomType {
	return HyperedgeAtomType
}

func (h *hyperedge) GetLocation() Location {
	var loc Location
	copy(loc[:32], h.appAddress[:])
	copy(loc[32:], h.dataAddress[:])
	return loc
}

func (h *hyperedge) GetAppAddress() [32]byte {
	return h.appAddress
}

func (h *hyperedge) GetDataAddress() [32]byte {
	return h.dataAddress
}

func (h *hyperedge) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(h.extrinsics); err != nil {
		return nil
	}
	return append(
		append(
			append(
				[]byte{0x01},
				h.appAddress[:]...,
			),
			h.dataAddress[:]...,
		),
		buf.Bytes()...,
	)
}

func (h *hyperedge) AddExtrinsic(a Atom) {
	id := a.GetID()
	atomType := []byte{0x00}
	if a.GetAtomType() == HyperedgeAtomType {
		atomType = []byte{0x01}
	}
	h.extTree.Insert(id[:], append(atomType, id[:]...), nil, a.GetSize())
	h.extrinsics[id] = a
}

func (h *hyperedge) RemoveExtrinsic(a Atom) {
	id := a.GetID()
	h.extTree.Delete(id[:])
	delete(h.extrinsics, id)
}

func (h *hyperedge) GetExtrinsics() map[[64]byte]Atom {
	ext := make(map[[64]byte]Atom)
	for id := range h.extrinsics {
		ext[id] = h.extrinsics[id]
	}
	return ext
}

func (h *hyperedge) Commit() []byte {
	return h.extTree.Commit(false)
}

type ShardAddress struct {
	L1 [3]byte
	L2 [32]byte
	L3 [32]byte
}

type ShardKey struct {
	L1 [3]byte
	L2 [32]byte
}

func GetShardAddress(a Atom) ShardAddress {
	appAddress := a.GetAppAddress()
	dataAddress := a.GetDataAddress()

	return ShardAddress{
		L1: [3]byte(p2p.GetBloomFilterIndices(appAddress[:], 256, 3)),
		L2: [32]byte(append([]byte{}, appAddress[:]...)),
		L3: [32]byte(append([]byte{}, dataAddress[:]...)),
	}
}

func GetShardKey(a Atom) ShardKey {
	s := GetShardAddress(a)
	return ShardKey{L1: s.L1, L2: s.L2}
}

type IdSet struct {
	dirty    bool
	atomType AtomType
	atoms    map[[64]byte]Atom
	tree     *crypto.VectorCommitmentTree
}

func NewIdSet(atomType AtomType) *IdSet {
	return &IdSet{
		dirty:    false,
		atomType: atomType,
		atoms:    make(map[[64]byte]Atom),
		tree:     &crypto.VectorCommitmentTree{},
	}
}

func (set *IdSet) FromBytes(treeData []byte) error {
	set.tree = &crypto.VectorCommitmentTree{}
	var b bytes.Buffer
	b.Write(treeData)
	dec := gob.NewDecoder(&b)
	if err := dec.Decode(set.tree); err != nil {
		return errors.Wrap(err, "load set")
	}

	for _, leaf := range crypto.GetAllLeaves(set.tree.Root) {
		set.atoms[[64]byte(leaf.Key)] = atomFromBytes(leaf.Value)
	}

	return nil
}

func (set *IdSet) IsDirty() bool {
	return set.dirty
}

func (set *IdSet) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(set.tree); err != nil {
		return nil
	}

	return buf.Bytes()
}

func (set *IdSet) Add(atom Atom) error {
	if atom.GetAtomType() != set.atomType {
		return ErrInvalidAtomType
	}

	id := atom.GetID()
	set.atoms[id] = atom
	set.dirty = true
	return set.tree.Insert(id[:], atom.ToBytes(), atom.Commit(), atom.GetSize())
}

func (set *IdSet) GetSize() *big.Int {
	size := set.tree.GetSize()
	if size == nil {
		size = big.NewInt(0)
	}
	return size
}

func (set *IdSet) Delete(atom Atom) bool {
	if atom.GetAtomType() != set.atomType {
		return false
	}

	id := atom.GetID()
	if err := set.tree.Delete(id[:]); err != nil {
		return false
	}

	set.dirty = true
	delete(set.atoms, id)

	return true
}

func (set *IdSet) Has(key [64]byte) bool {
	_, ok := set.atoms[key]
	return ok
}

type Hypergraph struct {
	size             *big.Int
	vertexAdds       map[ShardKey]*IdSet
	vertexRemoves    map[ShardKey]*IdSet
	hyperedgeAdds    map[ShardKey]*IdSet
	hyperedgeRemoves map[ShardKey]*IdSet
}

func NewHypergraph() *Hypergraph {
	return &Hypergraph{
		size:             big.NewInt(0),
		vertexAdds:       make(map[ShardKey]*IdSet),
		vertexRemoves:    make(map[ShardKey]*IdSet),
		hyperedgeAdds:    make(map[ShardKey]*IdSet),
		hyperedgeRemoves: make(map[ShardKey]*IdSet),
	}
}

func (hg *Hypergraph) GetVertexAdds() map[ShardKey]*IdSet {
	return hg.vertexAdds
}

func (hg *Hypergraph) GetVertexRemoves() map[ShardKey]*IdSet {
	return hg.vertexRemoves
}

func (hg *Hypergraph) GetHyperedgeAdds() map[ShardKey]*IdSet {
	return hg.hyperedgeAdds
}

func (hg *Hypergraph) GetHyperedgeRemoves() map[ShardKey]*IdSet {
	return hg.hyperedgeRemoves
}

func (hg *Hypergraph) Commit() [][]byte {
	commits := [][]byte{}
	for _, vertexAdds := range hg.vertexAdds {
		commits = append(commits, vertexAdds.tree.Commit(false))
	}
	for _, vertexRemoves := range hg.vertexRemoves {
		commits = append(commits, vertexRemoves.tree.Commit(false))
	}
	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		commits = append(commits, hyperedgeAdds.tree.Commit(false))
	}
	for _, hyperedgeRemoves := range hg.hyperedgeRemoves {
		commits = append(commits, hyperedgeRemoves.tree.Commit(false))
	}
	return commits
}

func (hg *Hypergraph) ImportFromBytes(
	atomType AtomType,
	phaseType PhaseType,
	shardKey ShardKey,
	data []byte,
) error {
	set := NewIdSet(atomType)
	if err := set.FromBytes(data); err != nil {
		return errors.Wrap(err, "import from bytes")
	}

	switch atomType {
	case VertexAtomType:
		switch phaseType {
		case AddsPhaseType:
			hg.size.Add(hg.size, set.GetSize())
			hg.vertexAdds[shardKey] = set
		case RemovesPhaseType:
			hg.size.Sub(hg.size, set.GetSize())
			hg.vertexRemoves[shardKey] = set
		}
	case HyperedgeAtomType:
		switch phaseType {
		case AddsPhaseType:
			hg.size.Add(hg.size, set.GetSize())
			hg.hyperedgeAdds[shardKey] = set
		case RemovesPhaseType:
			hg.size.Sub(hg.size, set.GetSize())
			hg.hyperedgeRemoves[shardKey] = set
		}
	}

	return nil
}

func (hg *Hypergraph) GetSize() *big.Int {
	return hg.size
}

func (hg *Hypergraph) getOrCreateIdSet(
	shardAddr ShardKey,
	addMap map[ShardKey]*IdSet,
	removeMap map[ShardKey]*IdSet,
	atomType AtomType,
) (*IdSet, *IdSet) {
	if _, ok := addMap[shardAddr]; !ok {
		addMap[shardAddr] = NewIdSet(atomType)
	}
	if _, ok := removeMap[shardAddr]; !ok {
		removeMap[shardAddr] = NewIdSet(atomType)
	}
	return addMap[shardAddr], removeMap[shardAddr]
}

func (hg *Hypergraph) AddVertex(v Vertex) error {
	shardAddr := GetShardKey(v)
	addSet, _ := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
	)
	hg.size.Add(hg.size, v.GetSize())
	return errors.Wrap(addSet.Add(v), "add vertex")
}

func (hg *Hypergraph) AddHyperedge(h Hyperedge) error {
	if !hg.LookupAtomSet(&h.(*hyperedge).extrinsics) {
		return ErrMissingExtrinsics
	}
	shardAddr := GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
	)
	id := h.GetID()
	if !removeSet.Has(id) {
		hg.size.Add(hg.size, h.GetSize())
		return errors.Wrap(addSet.Add(h), "add hyperedge")
	}
	return nil
}

func (hg *Hypergraph) RemoveVertex(v Vertex) error {
	shardKey := GetShardKey(v)
	if !hg.LookupVertex(v.(*vertex)) {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.vertexAdds,
			hg.vertexRemoves,
			VertexAtomType,
		)
		if err := addSet.Add(v); err != nil {
			return errors.Wrap(err, "remove vertex")
		}
		return errors.Wrap(removeSet.Add(v), "remove vertex")
	}

	id := v.GetID()

	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*hyperedge); ok {
				if _, ok := he.extrinsics[id]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
	)
	hg.size.Sub(hg.size, v.GetSize())
	err := removeSet.Add(v)
	return err
}

func (hg *Hypergraph) RemoveHyperedge(h Hyperedge) error {
	shardKey := GetShardKey(h)
	wasPresent := hg.LookupHyperedge(h.(*hyperedge))
	if !wasPresent {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.hyperedgeAdds,
			hg.hyperedgeRemoves,
			HyperedgeAtomType,
		)
		if err := addSet.Add(h); err != nil {
			return errors.Wrap(err, "remove hyperedge")
		}

		return errors.Wrap(removeSet.Add(h), "remove hyperedge")
	}

	id := h.GetID()
	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*hyperedge); ok {
				if _, ok := he.extrinsics[id]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
	)
	hg.size.Sub(hg.size, h.GetSize())
	err := removeSet.Add(h)
	return err
}

func (hg *Hypergraph) LookupVertex(v Vertex) bool {
	shardAddr := GetShardKey(v)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
	)
	id := v.GetID()
	return addSet.Has(id) && !removeSet.Has(id)
}

func (hg *Hypergraph) LookupHyperedge(h Hyperedge) bool {
	shardAddr := GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
	)
	id := h.GetID()
	return hg.LookupAtomSet(&h.(*hyperedge).extrinsics) && addSet.Has(id) && !removeSet.Has(id)
}

func (hg *Hypergraph) LookupAtom(a Atom) bool {
	switch v := a.(type) {
	case *vertex:
		return hg.LookupVertex(v)
	case *hyperedge:
		return hg.LookupHyperedge(v)
	default:
		return false
	}
}

func (hg *Hypergraph) LookupAtomSet(atomSet *map[[64]byte]Atom) bool {
	for _, atom := range *atomSet {
		if !hg.LookupAtom(atom) {
			return false
		}
	}
	return true
}

func (hg *Hypergraph) Within(a, h Atom) bool {
	if he, ok := h.(*hyperedge); ok {
		addr := a.GetID()
		if _, ok := he.extrinsics[addr]; ok || a.GetID() == h.GetID() {
			return true
		}
		for _, extrinsic := range he.extrinsics {
			if nestedHe, ok := extrinsic.(*hyperedge); ok {
				if hg.LookupHyperedge(nestedHe) && hg.Within(a, nestedHe) {
					return true
				}
			}
		}
	}
	return false
}

func (hg *Hypergraph) GetReconciledVertexSetForShard(
	shardKey ShardKey,
) *IdSet {
	vertices := NewIdSet(VertexAtomType)

	if addSet, ok := hg.vertexAdds[shardKey]; ok {
		removeSet := hg.vertexRemoves[shardKey]
		for id, v := range addSet.atoms {
			if !removeSet.Has(id) {
				vertices.Add(v)
			}
		}
	}

	return vertices
}

func (hg *Hypergraph) GetReconciledHyperedgeSetForShard(
	shardKey ShardKey,
) *IdSet {
	hyperedges := NewIdSet(HyperedgeAtomType)

	if addSet, ok := hg.hyperedgeAdds[shardKey]; ok {
		removeSet := hg.hyperedgeRemoves[shardKey]
		for _, h := range addSet.atoms {
			if !removeSet.Has(h.GetID()) {
				hyperedges.Add(h)
			}
		}
	}

	return hyperedges
}
