package blossomsub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// Test that when BlossomSub receives too many IWANT messages from a peer
// for the same message ID, it cuts off the peer
func TestBlossomSubAttackSpamIWANT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create legitimate and attacker hosts
	hosts := getDefaultHosts(t, 2)
	legit := hosts[0]
	attacker := hosts[1]

	// Set up BlossomSub on the legit host
	ps, err := NewBlossomSub(ctx, legit)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to mybitmask on the legit host
	mybitmask := []byte{0x20, 0x00, 0x00}

	// Wait a bit after the last message before checking we got the
	// right number of messages
	msgWaitMax := 10 * time.Second
	msgCount := 0
	msgTimer := time.NewTimer(msgWaitMax)

	// Checks we received the right number of messages
	checkMsgCount := func() {
		// After the original message from the legit host, we keep sending
		// IWANT until it stops replying. So the number of messages is
		// <original message> + BlossomSubGossipRetransmission
		exp := 1 + BlossomSubGossipRetransmission
		if msgCount != exp {
			panic(fmt.Sprintf("Expected %d messages, got %d", exp, msgCount))
		}
	}

	bitmasks, err := ps.Join(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	// Used to publish a message with random data
	publishMsg := func() {
		data := make([]byte, 16)
		rand.Read(data)

		if err := bitmasks[0].Publish(ctx, bitmasks[0].bitmask, data); err != nil {
			t.Fatal(err)
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgCount()
			cancel()
			return
		case <-ctx.Done():
			checkMsgCount()
		}
	}()

	newMockBS(ctx, t, attacker, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the legit host connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			sub := sub
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the legit host
					// received and processed the subscribe + graft
					time.Sleep(1 * time.Second)

					// Publish a message from the legit host
					publishMsg()
				}()
			}
		}

		// Each time the legit host sends a message
		for _, msg := range irpc.GetPublish() {
			// Increment the number of messages and reset the timer
			msgCount++
			msgTimer.Reset(msgWaitMax)

			// Shouldn't get more than the expected number of messages
			exp := 1 + BlossomSubGossipRetransmission
			if msgCount > exp {
				cancel()
				t.Fatal("Received too many responses")
			}

			// Send an IWANT with the message ID, causing the legit host
			// to send another message (until it cuts off the attacker for
			// being spammy)
			iwantlst := [][]byte{DefaultMsgIdFn(msg)}
			iwant := []*pb.ControlIWant{{MessageIDs: iwantlst}}
			orpc := rpcWithControl(nil, nil, iwant, nil, nil, nil)
			writeMsg(orpc.RPC)
		}
	})

	connect(t, hosts[0], hosts[1])

	time.Sleep(100 * time.Millisecond)

	_, err = ps.Subscribe(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
}

// Test that BlossomSub only responds to IHAVE with IWANT once per heartbeat
func TestBlossomSubAttackSpamIHAVE(t *testing.T) {
	originalBlossomSubIWantFollowupTime := BlossomSubIWantFollowupTime
	BlossomSubIWantFollowupTime = 10 * time.Second
	defer func() {
		BlossomSubIWantFollowupTime = originalBlossomSubIWantFollowupTime
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create legitimate and attacker hosts
	hosts := getDefaultHosts(t, 2)
	legit := hosts[0]
	attacker := hosts[1]

	// Set up BlossomSub on the legit host
	ps, err := NewBlossomSub(ctx, legit,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore:       func(peer.ID) float64 { return 0 },
				BehaviourPenaltyWeight: -1,
				BehaviourPenaltyDecay:  ScoreParameterDecay(time.Minute),
				DecayInterval:          DefaultDecayInterval,
				DecayToZero:            DefaultDecayToZero,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -100,
				PublishThreshold:  -500,
				GraylistThreshold: -1000,
			}))
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to mybitmask on the legit host
	mybitmask := []byte{0x20, 0x00, 0x00}
	_, err = ps.Subscribe(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	iWantCount := 0
	iWantCountMx := sync.Mutex{}
	getIWantCount := func() int {
		iWantCountMx.Lock()
		defer iWantCountMx.Unlock()
		return iWantCount
	}
	addIWantCount := func(i int) {
		iWantCountMx.Lock()
		defer iWantCountMx.Unlock()
		iWantCount += i
	}

	newMockBS(ctx, t, attacker, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the legit host connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			sub := sub
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					defer cancel()

					// Wait for a short interval to make sure the legit host
					// received and processed the subscribe + graft
					time.Sleep(20 * time.Millisecond)

					// Send a bunch of IHAVEs
					for i := 0; i < 3*BlossomSubMaxIHaveLength; i++ {
						ihavelst := [][]byte{[]byte("someid" + strconv.Itoa(i))}
						ihave := []*pb.ControlIHave{{Bitmask: sub.Bitmask, MessageIDs: ihavelst}}
						orpc := rpcWithControl(nil, ihave, nil, nil, nil, nil)
						writeMsg(orpc.RPC)
					}

					select {
					case <-ctx.Done():
						return
					case <-time.After(BlossomSubHeartbeatInterval):
					}

					// Should have hit the maximum number of IWANTs per peer
					// per heartbeat
					iwc := getIWantCount()
					if iwc > BlossomSubMaxIHaveLength {
						t.Errorf("Expecting max %d IWANTs per heartbeat but received %d", BlossomSubMaxIHaveLength, iwc)
						return // cannot call t.Fatalf in a non-test goroutine
					}
					firstBatchCount := iwc

					// the score should still be 0 because we haven't broken any promises yet
					score := ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
					if score != 0 {
						t.Errorf("Expected 0 score, but got %f", score)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Send a bunch of IHAVEs
					for i := 0; i < 3*BlossomSubMaxIHaveLength; i++ {
						ihavelst := [][]byte{[]byte("someid" + strconv.Itoa(i+100))}
						ihave := []*pb.ControlIHave{{Bitmask: sub.Bitmask, MessageIDs: ihavelst}}
						orpc := rpcWithControl(nil, ihave, nil, nil, nil, nil)
						writeMsg(orpc.RPC)
					}

					select {
					case <-ctx.Done():
						return
					case <-time.After(BlossomSubHeartbeatInterval):
					}

					// Should have sent more IWANTs after the heartbeat
					iwc = getIWantCount()
					if iwc == firstBatchCount {
						t.Error("Expecting to receive more IWANTs after heartbeat but did not")
						return // cannot call t.Fatalf in a non-test goroutine
					}
					// Should not be more than the maximum per heartbeat
					if iwc-firstBatchCount > BlossomSubMaxIHaveLength {
						t.Errorf("Expecting max %d IWANTs per heartbeat but received %d", BlossomSubMaxIHaveLength, iwc-firstBatchCount)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					select {
					case <-ctx.Done():
						return
					case <-time.After(BlossomSubIWantFollowupTime):
					}

					// The score should now be negative because of broken promises
					score = ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
					if score >= 0 {
						t.Errorf("Expected negative score, but got %f", score)
						return // cannot call t.Fatalf in a non-test goroutine
					}
				}()
			}
		}

		// Record the count of received IWANT messages
		if ctl := irpc.GetControl(); ctl != nil {
			addIWantCount(len(ctl.GetIwant()))
		}
	})

	connect(t, hosts[0], hosts[1])

	<-ctx.Done()
}

// Test that when BlossomSub receives GRAFT for an unknown bitmask, it ignores
// the request
func TestBlossomSubAttackGRAFTNonExistentBitmask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create legitimate and attacker hosts
	hosts := getDefaultHosts(t, 2)
	legit := hosts[0]
	attacker := hosts[1]

	// Set up BlossomSub on the legit host
	ps, err := NewBlossomSub(ctx, legit)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to mybitmask on the legit host
	mybitmask := []byte{0x20, 0x00, 0x00}
	_, err = ps.Subscribe(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	// Checks that we haven't received any PRUNE message
	pruneCount := 0
	checkForPrune := func() {
		// We send a GRAFT for a non-existent bitmask so we shouldn't
		// receive a PRUNE in response
		if pruneCount != 0 {
			t.Fatalf("Got %d unexpected PRUNE messages", pruneCount)
		}
	}

	newMockBS(ctx, t, attacker, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the legit host connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			sub := sub
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				// Graft to the peer on a non-existent bitmask
				nonExistentBitmask := []byte{0x20, 0x00, 0x00, 0x02, 0xff, 0xff}
				writeMsg(&pb.RPC{
					Control: &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: nonExistentBitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the legit host
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// We shouldn't get any prune messages becaue the bitmask
					// doesn't exist
					checkForPrune()
					cancel()
				}()
			}
		}

		// Record the count of received PRUNE messages
		if ctl := irpc.GetControl(); ctl != nil {
			pruneCount += len(ctl.GetPrune())
		}
	})

	connect(t, hosts[0], hosts[1])

	<-ctx.Done()
}

// Test that when BlossomSub receives GRAFT for a peer that has been PRUNED,
// it penalizes through P7 and eventually graylists and ignores the requests if the
// GRAFTs are coming too fast
func TestBlossomSubAttackGRAFTDuringBackoff(t *testing.T) {
	originalBlossomSubPruneBackoff := BlossomSubPruneBackoff
	BlossomSubPruneBackoff = 200 * time.Millisecond
	originalBlossomSubGraftFloodThreshold := BlossomSubGraftFloodThreshold
	BlossomSubGraftFloodThreshold = 100 * time.Millisecond
	defer func() {
		BlossomSubPruneBackoff = originalBlossomSubPruneBackoff
		BlossomSubGraftFloodThreshold = originalBlossomSubGraftFloodThreshold
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create legitimate and attacker hosts
	hosts := getDefaultHosts(t, 2)
	legit := hosts[0]
	attacker := hosts[1]

	// Set up BlossomSub on the legit host
	ps, err := NewBlossomSub(ctx, legit,
		WithPeerScore(
			&PeerScoreParams{
				AppSpecificScore:       func(peer.ID) float64 { return 0 },
				BehaviourPenaltyWeight: -100,
				BehaviourPenaltyDecay:  ScoreParameterDecay(time.Minute),
				DecayInterval:          DefaultDecayInterval,
				DecayToZero:            DefaultDecayToZero,
			},
			&PeerScoreThresholds{
				GossipThreshold:   -100,
				PublishThreshold:  -500,
				GraylistThreshold: -1000,
			}))
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to mybitmask on the legit host
	mybitmask := []byte{0x20, 0x00, 0x00}
	_, err = ps.Subscribe(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	pruneCount := 0
	pruneCountMx := sync.Mutex{}
	getPruneCount := func() int {
		pruneCountMx.Lock()
		defer pruneCountMx.Unlock()
		return pruneCount
	}
	addPruneCount := func(i int) {
		pruneCountMx.Lock()
		defer pruneCountMx.Unlock()
		pruneCount += i
	}

	newMockBS(ctx, t, attacker, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the legit host connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			sub := sub
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the peer
				graft := []*pb.ControlGraft{{Bitmask: sub.Bitmask}}
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: graft},
				})

				go func() {
					defer cancel()

					// Wait for a short interval to make sure the legit host
					// received and processed the subscribe + graft
					time.Sleep(20 * time.Millisecond)

					// No PRUNE should have been sent at this stage
					pc := getPruneCount()
					if pc != 0 {
						t.Errorf("Expected %d PRUNE messages but got %d", 0, pc)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Send a PRUNE to remove the attacker node from the legit
					// host's mesh
					var prune []*pb.ControlPrune
					prune = append(prune, &pb.ControlPrune{Bitmask: sub.Bitmask})
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Prune: prune},
					})

					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}

					// No PRUNE should have been sent at this stage
					pc = getPruneCount()
					if pc != 0 {
						t.Errorf("Expected %d PRUNE messages but got %d", 0, pc)
						return // cannot call t.Fatalf in a non-test goroutine

					}

					// wait for the BlossomSubGraftFloodThreshold to pass before attempting another graft
					time.Sleep(BlossomSubGraftFloodThreshold + time.Millisecond)

					// Send a GRAFT to attempt to rejoin the mesh
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Graft: graft},
					})

					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}

					// We should have been peanalized by the peer for sending before the backoff has expired
					// but should still receive a PRUNE because we haven't dropped below GraylistThreshold
					// yet.
					pc = getPruneCount()
					if pc != 1 {
						t.Errorf("Expected %d PRUNE messages but got %d", 1, pc)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					score1 := ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
					if score1 >= 0 {
						t.Errorf("Expected negative score, but got %f", score1)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Send a GRAFT again to attempt to rejoin the mesh
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Graft: graft},
					})

					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}

					// we are before the flood threshold so we should be penalized twice, but still get
					// a PRUNE because we are before the flood threshold
					pc = getPruneCount()
					if pc != 2 {
						t.Errorf("Expected %d PRUNE messages but got %d", 2, pc)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					score2 := ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
					if score2 >= score1 {
						t.Errorf("Expected score below %f, but got %f", score1, score2)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Send another GRAFT; this should get us a PRUNE, but penalize us below the graylist threshold
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Graft: graft},
					})

					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}

					pc = getPruneCount()
					if pc != 3 {
						t.Errorf("Expected %d PRUNE messages but got %d", 3, pc)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					score3 := ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
					if score3 >= score2 {
						t.Errorf("Expected score below %f, but got %f", score2, score3)
						return // cannot call t.Fatalf in a non-test goroutine
					}
					if score3 >= -1000 {
						t.Errorf("Expected score below %f, but got %f", -1000.0, score3)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Wait for the PRUNE backoff to expire and try again; this time we should fail
					// because we are below the graylist threshold, so our RPC should be ignored and
					// we should get no PRUNE back
					select {
					case <-ctx.Done():
						return
					case <-time.After(BlossomSubPruneBackoff + time.Millisecond):
					}

					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Graft: graft},
					})

					select {
					case <-ctx.Done():
						return
					case <-time.After(20 * time.Millisecond):
					}

					pc = getPruneCount()
					if pc != 3 {
						t.Errorf("Expected %d PRUNE messages but got %d", 3, pc)
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// make sure we are _not_ in the mesh
					res := make(chan bool)
					ps.eval <- func() {
						mesh := ps.rt.(*BlossomSubRouter).mesh[string(mybitmask)]
						_, inMesh := mesh[attacker.ID()]
						res <- inMesh
					}

					inMesh := <-res
					if inMesh {
						t.Error("Expected to not be in the mesh of the legitimate host")
						return // cannot call t.Fatal in a non-test goroutine
					}
				}()
			}
		}

		if ctl := irpc.GetControl(); ctl != nil {
			addPruneCount(len(ctl.GetPrune()))
		}
	})

	connect(t, hosts[0], hosts[1])

	<-ctx.Done()
}

type bsAttackInvalidMsgTracer struct {
	rejectCount int
}

func (t *bsAttackInvalidMsgTracer) Trace(evt *pb.TraceEvent) {
	// fmt.Printf("    %s %s\n", evt.Type, evt)
	if evt.GetType() == pb.TraceEvent_REJECT_MESSAGE {
		t.rejectCount++
	}
}

// Test that when BlossomSub receives a lot of invalid messages from
// a peer it should graylist the peer
func TestBlossomSubAttackInvalidMessageSpam(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create legitimate and attacker hosts
	hosts := getDefaultHosts(t, 2)
	legit := hosts[0]
	attacker := hosts[1]

	mybitmask := []byte{0x20, 0x00, 0x00}

	// Create parameters with reasonable default values
	params := &PeerScoreParams{
		AppSpecificScore:            func(peer.ID) float64 { return 0 },
		IPColocationFactorWeight:    0,
		IPColocationFactorThreshold: 1,
		DecayInterval:               5 * time.Second,
		DecayToZero:                 0.01,
		RetainScore:                 10 * time.Second,
		Bitmasks:                    make(map[string]*BitmaskScoreParams),
	}
	params.Bitmasks[string(mybitmask)] = &BitmaskScoreParams{
		BitmaskWeight:                   0.25,
		TimeInMeshWeight:                0.0027,
		TimeInMeshQuantum:               time.Second,
		TimeInMeshCap:                   3600,
		FirstMessageDeliveriesWeight:    0.664,
		FirstMessageDeliveriesDecay:     0.9916,
		FirstMessageDeliveriesCap:       1500,
		MeshMessageDeliveriesWeight:     -0.25,
		MeshMessageDeliveriesDecay:      0.97,
		MeshMessageDeliveriesCap:        400,
		MeshMessageDeliveriesThreshold:  100,
		MeshMessageDeliveriesActivation: 30 * time.Second,
		MeshMessageDeliveriesWindow:     5 * time.Minute,
		MeshFailurePenaltyWeight:        -0.25,
		MeshFailurePenaltyDecay:         0.997,
		InvalidMessageDeliveriesWeight:  -99,
		InvalidMessageDeliveriesDecay:   0.9994,
	}
	thresholds := &PeerScoreThresholds{
		GossipThreshold:   -100,
		PublishThreshold:  -200,
		GraylistThreshold: -300,
		AcceptPXThreshold: 0,
	}

	// Set up BlossomSub on the legit host
	tracer := &bsAttackInvalidMsgTracer{}
	ps, err := NewBlossomSub(ctx, legit,
		WithEventTracer(tracer),
		WithPeerScore(params, thresholds),
		WithMessageSignaturePolicy(StrictSign),
	)
	if err != nil {
		t.Fatal(err)
	}

	attackerScore := func() float64 {
		return ps.rt.(*BlossomSubRouter).score.Score(attacker.ID())
	}

	// Subscribe to mybitmask on the legit host
	_, err = ps.Subscribe(mybitmask)
	if err != nil {
		t.Fatal(err)
	}

	pruneCount := 0
	pruneCountMx := sync.Mutex{}
	getPruneCount := func() int {
		pruneCountMx.Lock()
		defer pruneCountMx.Unlock()
		return pruneCount
	}
	addPruneCount := func(i int) {
		pruneCountMx.Lock()
		defer pruneCountMx.Unlock()
		pruneCount += i
	}

	newMockBS(ctx, t, attacker, func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// When the legit host connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					defer cancel()

					// Attacker score should start at zero
					if attackerScore() != 0 {
						t.Errorf("Expected attacker score to be zero but it's %f", attackerScore())
						return // cannot call t.Fatalf in a non-test goroutine
					}

					// Send a bunch of messages with no signature (these will
					// fail validation and reduce the attacker's score)
					for i := 0; i < 100; i++ {
						msg := &pb.Message{
							Data:    []byte("some data" + strconv.Itoa(i)),
							Bitmask: mybitmask,
							From:    []byte(attacker.ID()),
							Seqno:   []byte{byte(i + 1)},
						}
						writeMsg(&pb.RPC{
							Publish: []*pb.Message{msg},
						})
					}

					// Wait for the initial heartbeat, plus a bit of padding
					select {
					case <-ctx.Done():
						return
					case <-time.After(100*time.Millisecond + BlossomSubHeartbeatInitialDelay):
					}

					// The attackers score should now have fallen below zero
					if attackerScore() >= 0 {
						t.Errorf("Expected attacker score to be less than zero but it's %f", attackerScore())
						return // cannot call t.Fatalf in a non-test goroutine
					}
					// There should be several rejected messages (because the signature was invalid)
					if tracer.rejectCount == 0 {
						t.Error("Expected message rejection but got none")
						return // cannot call t.Fatal in a non-test goroutine
					}
					// The legit node should have sent a PRUNE message
					pc := getPruneCount()
					if pc == 0 {
						t.Error("Expected attacker node to be PRUNED when score drops low enough")
						return // cannot call t.Fatal in a non-test goroutine
					}
				}()
			}
		}

		if ctl := irpc.GetControl(); ctl != nil {
			addPruneCount(len(ctl.GetPrune()))
		}
	})

	connect(t, hosts[0], hosts[1])

	<-ctx.Done()
}

// Test that when BlossomSub receives too many IDONTWANT messages from a peer
func TestBlossomSubAttackSpamIDONTWANT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosts := getDefaultHosts(t, 3)

	msgID := func(pmsg *pb.Message) []byte {
		mid := sha256.Sum256(pmsg.GetData())
		return mid[:]
	}

	psubs := make([]*PubSub, 2)
	psubs[0] = getBlossomSub(ctx, hosts[0], WithMessageIdFn(msgID))
	psubs[1] = getBlossomSub(ctx, hosts[1], WithMessageIdFn(msgID))

	bitmask := []byte{0x20, 0x00, 0x00}
	for _, ps := range psubs {
		_, err := ps.Subscribe(bitmask)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Wait a bit after the last message before checking the result
	msgWaitMax := time.Second + BlossomSubHeartbeatInterval
	msgTimer := time.NewTimer(msgWaitMax)

	// Checks we received some messages
	var midsMu sync.RWMutex
	var expMid []byte
	var actMids [][]byte
	checkMsgs := func() {
		midsMu.RLock()
		defer midsMu.RUnlock()
		if len(actMids) == 0 {
			t.Fatalf("Expected some messages when the maximum number of IDONTWANTs is reached")
		}
		if !bytes.Equal(actMids[0], expMid) {
			t.Fatalf("The expected message is incorrect")
		}
		if len(actMids) > 1 {
			t.Fatalf("The spam prevention should be reset after the heartbeat")
		}
	}

	// Wait for the timer to expire
	go func() {
		select {
		case <-msgTimer.C:
			checkMsgs()
			cancel()
			return
		case <-ctx.Done():
			checkMsgs()
		}
	}()

	newMockBS(ctx, t, hosts[2], func(writeMsg func(*pb.RPC), irpc *pb.RPC) {
		// Each time the host receives a message
		midsMu.Lock()
		for _, msg := range irpc.GetPublish() {
			actMids = append(actMids, msgID(msg))
		}
		midsMu.Unlock()
		// When the middle peer connects it will send us its subscriptions
		for _, sub := range irpc.GetSubscriptions() {
			if sub.GetSubscribe() {
				// Reply by subcribing to the bitmask and grafting to the middle peer
				writeMsg(&pb.RPC{
					Subscriptions: []*pb.RPC_SubOpts{{Subscribe: sub.Subscribe, Bitmask: sub.Bitmask}},
					Control:       &pb.ControlMessage{Graft: []*pb.ControlGraft{{Bitmask: sub.Bitmask}}},
				})

				go func() {
					// Wait for a short interval to make sure the middle peer
					// received and processed the subscribe + graft
					time.Sleep(100 * time.Millisecond)

					// Generate a message and send IDONTWANT to the middle peer
					data := make([]byte, 16)
					var mid []byte
					for i := 0; i < 1+BlossomSubMaxIDontWantMessages; i++ {
						rand.Read(data)
						mid = msgID(&pb.Message{Data: data})
						writeMsg(&pb.RPC{
							Control: &pb.ControlMessage{Idontwant: []*pb.ControlIDontWant{{MessageIDs: [][]byte{mid}}}},
						})
					}
					// The host should receives this message id because the maximum was reached
					midsMu.Lock()
					expMid = mid
					midsMu.Unlock()

					// Wait for a short interval to make sure the middle peer
					// received and processed the IDONTWANTs
					time.Sleep(100 * time.Millisecond)

					// Publish the message from the first peer
					if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
						t.Error(err)
						return // cannot call t.Fatal in a non-test goroutine
					}

					// Wait for the next heartbeat so that the prevention will be reset
					select {
					case <-ctx.Done():
						return
					case <-time.After(BlossomSubHeartbeatInterval):
					}

					// Test IDONTWANT again to see that it now works again
					rand.Read(data)
					mid = msgID(&pb.Message{Data: data})
					writeMsg(&pb.RPC{
						Control: &pb.ControlMessage{Idontwant: []*pb.ControlIDontWant{{MessageIDs: [][]byte{mid}}}},
					})
					time.Sleep(100 * time.Millisecond)
					if err := psubs[0].Publish(ctx, bitmask, data); err != nil {
						t.Error(err)
						return // cannot call t.Fatal in a non-test goroutine
					}
				}()
			}
		}
	})

	connect(t, hosts[0], hosts[1])
	connect(t, hosts[1], hosts[2])

	<-ctx.Done()
}

type MockBSOnRead func(writeMsg func(*pb.RPC), irpc *pb.RPC)

func newMockBS(ctx context.Context, t *testing.T, attacker host.Host, onReadMsg MockBSOnRead) {
	newMockBSWithVersion(ctx, t, attacker, BlossomSubID_v21, onReadMsg)
}

func newMockBSWithVersion(ctx context.Context, t *testing.T, attacker host.Host, blossomSubID protocol.ID, onReadMsg MockBSOnRead) {
	// Listen on the BlossomSub protocol
	const maxMessageSize = 1024 * 1024
	attacker.SetStreamHandler(blossomSubID, func(stream network.Stream) {
		// When an incoming stream is opened, set up an outgoing stream
		p := stream.Conn().RemotePeer()
		ostream, err := attacker.NewStream(ctx, p, blossomSubID)
		if err != nil {
			t.Fatal(err)
		}

		r := msgio.NewVarintReaderSize(stream, maxMessageSize)
		w := msgio.NewVarintWriter(ostream)

		var irpc pb.RPC

		writeMsg := func(rpc *pb.RPC) {
			out, err := proto.Marshal(rpc)
			if err != nil {
				t.Fatalf("error writing RPC: %s", err)
			}
			if err = w.WriteMsg(out); err != nil {
				t.Fatalf("error writing RPC: %s", err)
			}
		}

		// Keep reading messages and responding
		for {
			// Bail out when the test finishes
			if ctx.Err() != nil {
				return
			}

			irpc.Reset()
			v, err := r.ReadMsg()

			// Bail out when the test finishes
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			err = proto.Unmarshal(v, &irpc)
			if err != nil {
				t.Fatal(err)
			}

			// Bail out when the test finishes
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			onReadMsg(writeMsg, &irpc)
		}
	})
}
