package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/dedis/kyber/share"
	"github.com/dedis/onet"
)

// Config holds all the parameters for the consensus protocol
type Config struct {
	Seed         int64           // seed to construct the PRNG => random beacon
	Public       *share.PubPoly  // public polynomial
	Share        *share.PriShare // private share
	Roster       *onet.Roster    // participants
	Threshold    int             // threshold of the threshold sharing scheme
	N            int             // length of participants
	BlockSize    int             // the size of the block in bytes
	Proposers    int             // how many nodes should propose a block
	BlockTime    int             // blocktime in seconds
	FinalizeTime int             // time T to wait during finalization
	StartTime    int64           // when to start the blockchain
}

// BlockHeader represents all the information regarding a block
type BlockHeader struct {
	Round   int    // round of the block
	Owner   int    // index of the owner of the block
	Root    string // hash of the data
	PrvHash string // hash of the previous block
	PrvSig  []byte // signature of the previous block (i.e. notarization)
}

// Block represents how a block is stored locally
type Block struct {
	BlockHeader
	Blob []byte // the actual content
}

type Notarization struct {
	Hash      string
	Signature []byte
}

// BlockProposal is sent when a participants propose a new block
type BlockProposal struct {
	BlockHeader
	Blob    []byte // the actual content
	Partial []byte // partial signature over the header
}

// ProposalSignature represents the signature over a block
type SignatureProposal struct {
	BlockHeader        // Header that represents the block
	Blob        []byte // data blob as mentionned in the paper
	Signer      int    // Signer's index in the original list of participants
	Partial     []byte // Partial signature from the signer
}

// Hash returns the hash in hexadecimal of the header
func (h *BlockHeader) Hash() string {
	hash := Suite.Hash()
	binary.Write(hash, binary.BigEndian, h.Owner)
	binary.Write(hash, binary.BigEndian, h.Round)
	hash.Write([]byte(h.PrvHash))
	hash.Write([]byte(h.Root))
	hash.Write(h.PrvSig)
	buff := hash.Sum(nil)
	return hex.EncodeToString(buff)
}

var GenesisBlock = &Block{
	BlockHeader: BlockHeader{
		Round: 0,
		Owner: -1,
		Root:  "6afbc27f4ae8951a541be53038ca20d3a9f18f60a38b1dc2cd48a46ff5d26ace",
		// sha256("hello world")
		PrvHash: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
		// echo "hello world" | sha256sum | sha256sum
		PrvSig: []byte("3605ff73b6faec27aa78e311603e9fe2ef35bad82ccf46fc707814bfbdcc6f9e"),
	},
	Blob: []byte("Remember when you were young?"),
}

func rootHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
