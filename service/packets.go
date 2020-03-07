package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"go.dedis.ch/onet/network"
)

var BlockProposalType network.MessageTypeID
var NotarizedBlockType network.MessageTypeID
var SignatureProposalType network.MessageTypeID
var BeaconType network.MessageTypeID

func init() {
	BlockProposalType = network.RegisterMessage(&BlockProposal{})
	NotarizedBlockType = network.RegisterMessage(&NotarizedBlock{})
	SignatureProposalType = network.RegisterMessage(&SignatureProposal{})
	BeaconType = network.RegisterMessage(&BeaconPacket{})
}

// BlockHeader represents all the information regarding a block
type BlockHeader struct {
	Round      int    // round of the block
	Owner      int    // index of the owner of the block
	Root       string // hash of the data
	Randomness int64  // randomness of the round
	PrvHash    string // hash of the previous block
	PrvSig     []byte // signature of the previous block (i.e. notarization)
}

// Block represents how a block is stored locally
// Block is first sent from a block maker
type Block struct {
	BlockHeader
	Blob []byte // the actual content
}

type Notarization struct {
	Hash      string
	Signature []byte
}

// NotarizedBlock is a block that has been notarized, so it includes the block
// and the notarization associated
type NotarizedBlock struct {
	*Block
	*Notarization
}

// BlockProposal is a block proposed by a block maker
type BlockProposal Block

// ProposalSignature represents the signature over a block
type SignatureProposal struct {
	*Block
	Partial []byte // Partial signature from the signer
}

// Packet sent by the randomness beacon. Simulated DKG...
type BeaconPacket struct {
	Round      int
	Randomness int64
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

func rootHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// GenesisBlock is the first block of the chain
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
	Blob: []byte("Hello Genesis"),
}
