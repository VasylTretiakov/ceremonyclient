package blossomsub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestBlossomSubMatchingFn(t *testing.T) {
	customsubA100 := protocol.ID("/customsub_a/1.0.0")
	customsubA101Beta := protocol.ID("/customsub_a/1.0.1-beta")
	customsubB100 := protocol.ID("/customsub_b/1.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := getDefaultHosts(t, 4)
	psubs := []*PubSub{
		getBlossomSub(ctx, h[0], WithProtocolMatchFn(protocolNameMatch), WithBlossomSubProtocols([]protocol.ID{customsubA100, BlossomSubID_v2}, BlossomSubDefaultFeatures)),
		getBlossomSub(ctx, h[1], WithProtocolMatchFn(protocolNameMatch), WithBlossomSubProtocols([]protocol.ID{customsubA101Beta}, BlossomSubDefaultFeatures)),
		getBlossomSub(ctx, h[2], WithProtocolMatchFn(protocolNameMatch), WithBlossomSubProtocols([]protocol.ID{BlossomSubID_v2}, BlossomSubDefaultFeatures)),
		getBlossomSub(ctx, h[3], WithProtocolMatchFn(protocolNameMatch), WithBlossomSubProtocols([]protocol.ID{customsubB100}, BlossomSubDefaultFeatures)),
	}

	connect(t, h[0], h[1])
	connect(t, h[0], h[2])
	connect(t, h[0], h[3])

	// verify that the peers are connected
	time.Sleep(2 * time.Second)
	for i := 1; i < len(h); i++ {
		if len(h[0].Network().ConnsToPeer(h[i].ID())) == 0 {
			t.Fatal("expected a connection between peers")
		}
	}

	// build the mesh
	var subs [][]*Subscription
	var bitmasks [][]*Bitmask
	for _, ps := range psubs {
		b, err := ps.Join([]byte{0x00, 0x80, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		bitmasks = append(bitmasks, b)

		sub, err := ps.Subscribe([]byte{0x00, 0x80, 0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}

	time.Sleep(time.Second)

	// publish a message
	msg := []byte("message")
	bitmasks[0][0].Publish(ctx, bitmasks[0][0].bitmask, msg)

	assertReceive(t, subs[0], msg)
	assertReceive(t, subs[1], msg) // Should match via semver over CustomSub name, ignoring the version
	assertReceive(t, subs[2], msg) // Should match via BlossomSubID_v2

	// No message should be received because customsubA and customsubB have different names
	assertNeverReceives(t, subs[2], 1*time.Second)
}

func protocolNameMatch(base protocol.ID) func(protocol.ID) bool {
	return func(check protocol.ID) bool {
		baseName := strings.Split(string(base), "/")[1]
		checkName := strings.Split(string(check), "/")[1]
		return baseName == checkName
	}
}
