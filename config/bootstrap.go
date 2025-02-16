package config

import (
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// defaultBootstrapAddresses are the hardcoded bootstrap addresses.
var defaultBootstrapAddresses = []string{
	"/dns4/bootstrap-0.mainnet.filops.net/tcp/1347/p2p/12D3KooWCVe8MmsEMes2FzgTpt9fXtmCY7wrq91GRiaC8PHSCCBj",
	"/dns4/bootstrap-1.mainnet.filops.net/tcp/1347/p2p/12D3KooWCwevHg1yLCvktf2nvLu7L9894mcrJR4MsBCcm4syShVc",
	"/dns4/bootstrap-2.mainnet.filops.net/tcp/1347/p2p/12D3KooWEWVwHGn2yR36gKLozmb4YjDJGerotAPGxmdWZx2nxMC4",
	"/dns4/bootstrap-3.mainnet.filops.net/tcp/1347/p2p/12D3KooWKhgq8c7NQ9iGjbyK7v7phXvG6492HQfiDaGHLHLQjk7R",
	"/dns4/bootstrap-4.mainnet.filops.net/tcp/1347/p2p/12D3KooWL6PsFNPhYftrJzGgF5U18hFoaVhfGk7xwzD8yVrHJ3Uc",
	"/dns4/bootstrap-5.mainnet.filops.net/tcp/1347/p2p/12D3KooWLFynvDQiUpXoHroV1YxKHhPJgysQGH2k3ZGwtWzR4dFH",
	"/dns4/bootstrap-6.mainnet.filops.net/tcp/1347/p2p/12D3KooWP5MwCiqdMETF9ub1P3MbCvQCcfconnYHbWg6sUJcDRQQ",
	"/dns4/bootstrap-7.mainnet.filops.net/tcp/1347/p2p/12D3KooWRs3aY1p3juFjPy8gPN95PEQChm2QKGUCAdcDCC4EBMKf",
	"/dns4/bootstrap-8.mainnet.filops.net/tcp/1347/p2p/12D3KooWScFR7385LTyR4zU1bYdzSiiAb5rnNABfVahPvVSzyTkR",
	"/dns4/lotus-bootstrap.ipfsforce.com/tcp/41778/p2p/12D3KooWGhufNmZHF3sv48aQeS13ng5XVJZ9E6qy2Ms4VzqeUsHk",
	"/dns4/bootstrap-0.starpool.in/tcp/12757/p2p/12D3KooWGHpBMeZbestVEWkfdnC9u7p6uFHXL1n7m1ZBqsEmiUzz",
	"/dns4/bootstrap-1.starpool.in/tcp/12757/p2p/12D3KooWQZrGH1PxSNZPum99M1zNvjNFM33d1AAu5DcvdHptuU7u",
	"/dns4/node.glif.io/tcp/1235/p2p/12D3KooWBF8cpp65hp2u9LK5mh19x67ftAam84z9LsfaquTDSBpt",
	"/dns4/bootstrap-0.ipfsmain.cn/tcp/34721/p2p/12D3KooWQnwEGNqcM2nAcPtRR9rAX8Hrg4k9kJLCHoTR5chJfz6d",
	"/dns4/bootstrap-1.ipfsmain.cn/tcp/34723/p2p/12D3KooWMKxMkD5DMpSWsW7dBddKxKT7L2GgbNuckz9otxvkvByP",
}

// Bootstrap configures other nodes to connect to for the purpose of exchanging
// gossip pubsub. The nodes listed here must be running pubsub and must also be
// subscribed to the indexer/ingest topic. The peers can be other indexers, or
// IPFS nodes with pubsub enabled and subscribed to the topic.
type Bootstrap struct {
	// Peers is the local node's bootstrap peer addresses.
	Peers []string
	// MinimumPeers governs whether to bootstrap more connections. If the node
	// has less open connections than this number, it will open connections to
	// the bootstrap nodes. Set to 0 to disable bootstrapping.
	MinimumPeers int
}

// NewBootstrap returns Bootstrap with values set to their defaults.
func NewBootstrap() Bootstrap {
	return Bootstrap{
		Peers:        defaultBootstrapPeers(),
		MinimumPeers: 4,
	}
}

// ErrInvalidPeerAddr signals an address is not a valid peer address.
var ErrInvalidPeerAddr = errors.New("invalid peer address")

// PeerAddrs returns the bootstrap peers as a list of AddrInfo.
func (b Bootstrap) PeerAddrs() ([]peer.AddrInfo, error) {
	return parsePeers(b.Peers)
}

// SetPeers sets the bootstrap peers from a list of AddrInfo.
func (b *Bootstrap) SetPeers(addrs []peer.AddrInfo) {
	b.Peers = addrsToPeers(addrs)
}

// defaultBootstrapPeers returns the (parsed) set of default bootstrap peers.
// Panics on failure as that is a problem with the hardcoded addresses.
func defaultBootstrapPeers() []string {
	addrs, err := parsePeers(defaultBootstrapAddresses)
	if err != nil {
		panic(fmt.Sprintf("failed to parse hardcoded bootstrap peers: %s", err))
	}
	return addrsToPeers(addrs)
}

// parsePeers parses a peer list into a list of AddrInfo.
func parsePeers(addrs []string) ([]peer.AddrInfo, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	maddrs := make([]multiaddr.Multiaddr, len(addrs))
	for i, addr := range addrs {
		var err error
		maddrs[i], err = multiaddr.NewMultiaddr(addr)
		if err != nil {
			return nil, err
		}
	}
	return peer.AddrInfosFromP2pAddrs(maddrs...)
}

// addrsToPeers formats a list of AddrInfos as a peer list suitable for
// serialization.
func addrsToPeers(addrs []peer.AddrInfo) []string {
	peers := make([]string, 0, len(addrs))
	for _, pi := range addrs {
		addrs, err := peer.AddrInfoToP2pAddrs(&pi)
		if err != nil {
			// programmer error.
			panic(err)
		}
		for _, addr := range addrs {
			peers = append(peers, addr.String())
		}
	}
	return peers
}
