package schema_test

import (
	"fmt"
	"math/rand"
	"testing"

	stischema "github.com/filecoin-project/storetheindex/api/v0/ingest/schema"
	"github.com/filecoin-project/storetheindex/test/util"
	"github.com/ipld/go-ipld-prime"
	_ "github.com/ipld/go-ipld-prime/codec/dagjson"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/storage/memstore"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/test"
	"github.com/stretchr/testify/require"
)

func TestAdvertisement_SignAndVerify(t *testing.T) {
	rng := rand.New(rand.NewSource(1413))
	lsys := cidlink.DefaultLinkSystem()
	store := &memstore.Store{}
	lsys.SetReadStorage(store)
	lsys.SetWriteStorage(store)

	priv, pub, err := test.RandTestKeyPair(crypto.Ed25519, 256)
	require.NoError(t, err)
	peerID, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)

	ec := stischema.EntryChunk{
		Entries: util.RandomMultihashes(10, rng),
	}

	node, err := ec.ToNode()
	require.NoError(t, err)
	elnk, err := lsys.Store(ipld.LinkContext{}, stischema.Linkproto, node)
	require.NoError(t, err)

	adv := stischema.Advertisement{
		Provider: "12D3KooWKRyzVWW6ChFjQjK4miCty85Niy48tpPV95XdKu1BcvMA",
		Addresses: []string{
			"/ip4/127.0.0.1/tcp/9999",
		},
		Entries:   elnk,
		ContextID: []byte("test-context-id"),
		Metadata:  []byte("test-metadata"),
	}
	err = adv.Sign(priv)
	require.NoError(t, err)

	signerID, err := adv.VerifySignature()
	require.NoError(t, err)
	require.Equal(t, peerID, signerID)

	// Show that signature can be valid even though advertisement not signed by
	// provider ID.  This is why it is necessary to check that the signer ID is
	// the expected signed after verifying the signature is valid.
	provID, err := peer.Decode(adv.Provider)
	require.NoError(t, err)
	require.NotEqual(t, signerID, provID)

	// Verification fails if something in the advertisement changes
	adv.Provider = ""
	_, err = adv.VerifySignature()
	require.NotNil(t, err)
}

func TestAdvertisement_SignWithExtendedProviderAndVerify(t *testing.T) {
	rng := rand.New(rand.NewSource(1413))
	lsys := cidlink.DefaultLinkSystem()
	store := &memstore.Store{}
	lsys.SetReadStorage(store)
	lsys.SetWriteStorage(store)

	priv, pub, err := test.RandTestKeyPair(crypto.Ed25519, 256)
	require.NoError(t, err)
	peerID, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)

	ec := stischema.EntryChunk{
		Entries: util.RandomMultihashes(10, rng),
	}

	node, err := ec.ToNode()
	require.NoError(t, err)
	elnk, err := lsys.Store(ipld.LinkContext{}, stischema.Linkproto, node)
	require.NoError(t, err)

	ep1Priv, ep1PeerID, ep1Addrs := generateIdentityAndKey(t)
	ep2Priv, ep2PeerID, ep2Addrs := generateIdentityAndKey(t)
	mpPriv, mpPeerID, mpAddrs := generateIdentityAndKey(t)

	adv := stischema.Advertisement{
		Provider: mpPeerID.String(),
		Addresses: []string{
			"/ip4/127.0.0.1/tcp/9999",
		},
		Entries:   elnk,
		ContextID: []byte("test-context-id"),
		Metadata:  []byte("test-metadata"),
		ExtendedProvider: &stischema.ExtendedProvider{
			Providers: []stischema.Provider{
				{
					ID:        ep1PeerID.String(),
					Addresses: ep1Addrs,
					Metadata:  []byte("ep1-metadata"),
				},
				{
					ID:        ep2PeerID.String(),
					Addresses: ep2Addrs,
					Metadata:  []byte("ep2-metadata"),
				},
				{
					ID:        mpPeerID.String(),
					Addresses: mpAddrs,
					Metadata:  []byte("main-metadata"),
				},
			},
		},
	}

	err = adv.SignWithExtendedProviders(priv, func(p string) (crypto.PrivKey, error) {
		switch p {
		case ep1PeerID.String():
			return ep1Priv, nil
		case ep2PeerID.String():
			return ep2Priv, nil
		case mpPeerID.String():
			return mpPriv, nil
		default:
			return nil, fmt.Errorf("Unknown provider %s", p)
		}
	})

	require.NoError(t, err)

	signerID, err := adv.VerifySignature()
	require.NoError(t, err)
	require.Equal(t, peerID, signerID)

	// Show that signature can be valid even though advertisement not signed by
	// provider ID.  This is why it is necessary to check that the signer ID is
	// the expected signed after verifying the signature is valid.
	provID, err := peer.Decode(adv.Provider)
	require.NoError(t, err)
	require.NotEqual(t, signerID, provID)

	// Verification fails if something in the advertisement changes
	adv.Provider = ""
	_, err = adv.VerifySignature()
	require.NotNil(t, err)
}

func TestAdvertisement_SignFailsIfTopLevelProviderIsNotInExtendedList(t *testing.T) {
	rng := rand.New(rand.NewSource(1413))
	lsys := cidlink.DefaultLinkSystem()
	store := &memstore.Store{}
	lsys.SetReadStorage(store)
	lsys.SetWriteStorage(store)

	priv, _, err := test.RandTestKeyPair(crypto.Ed25519, 256)
	require.NoError(t, err)
	require.NoError(t, err)

	ec := stischema.EntryChunk{
		Entries: util.RandomMultihashes(10, rng),
	}

	node, err := ec.ToNode()
	require.NoError(t, err)
	elnk, err := lsys.Store(ipld.LinkContext{}, stischema.Linkproto, node)
	require.NoError(t, err)

	ep1Priv, ep1PeerID, ep1Addrs := generateIdentityAndKey(t)

	adv := stischema.Advertisement{
		Provider: "12D3KooWKRyzVWW6ChFjQjK4miCty85Niy48tpPV95XdKu1BcvMA",
		Addresses: []string{
			"/ip4/127.0.0.1/tcp/9999",
		},
		Entries:   elnk,
		ContextID: []byte("test-context-id"),
		Metadata:  []byte("test-metadata"),
		ExtendedProvider: &stischema.ExtendedProvider{
			Providers: []stischema.Provider{
				{
					ID:        ep1PeerID.String(),
					Addresses: ep1Addrs,
					Metadata:  []byte("ep1-metadata"),
				},
			},
		},
	}

	err = adv.SignWithExtendedProviders(priv, func(p string) (crypto.PrivKey, error) {
		switch p {
		case ep1PeerID.String():
			return ep1Priv, nil
		default:
			return nil, fmt.Errorf("Unknown provider %s", p)
		}
	})

	require.Error(t, err)
	require.Equal(t, "extended providers must contain provider from the encapsulating advertisement", err.Error())
}

func generateIdentityAndKey(t *testing.T) (crypto.PrivKey, peer.ID, []string) {
	priv, pub, err := test.RandTestKeyPair(crypto.Ed25519, 256)
	require.NoError(t, err)
	peerID, err := peer.IDFromPublicKey(pub)
	require.NoError(t, err)
	return priv, peerID, []string{"/ip4/127.0.0.1/tcp/9999", "/ip4/127.0.0.1/tcp/1111"}
}
