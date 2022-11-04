package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A ResetStreamFrame is a RESET_STREAM or RELIABLE_RESET_STREAM frame in QUIC
type ResetStreamFrame struct {
	StreamID     protocol.StreamID
	ErrorCode    qerr.StreamErrorCode
	FinalSize    protocol.ByteCount
	ReliableSize protocol.ByteCount
}

func parseResetStreamFrame(r *bytes.Reader, _ protocol.VersionNumber) (*ResetStreamFrame, error) {
	typ, err := r.ReadByte()
	if err != nil { // read the TypeByte
		return nil, err
	}

	sid, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	streamID := protocol.StreamID(sid)
	errorCode, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	bo, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	finalSize := protocol.ByteCount(bo)

	var reliableSize protocol.ByteCount
	if typ == 0x72 {
		rs, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		reliableSize = protocol.ByteCount(rs)
	}
	if reliableSize > finalSize {
		return nil, fmt.Errorf("RELIABLE_RESET_STREAM: reliable size can't be larger than final size (%d vs %d)", reliableSize, finalSize)
	}

	return &ResetStreamFrame{
		StreamID:     streamID,
		ErrorCode:    qerr.StreamErrorCode(errorCode),
		FinalSize:    finalSize,
		ReliableSize: reliableSize,
	}, nil
}

func (f *ResetStreamFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	typ := uint64(0x4)
	if f.ReliableSize > 0 {
		typ = 0x72
	}
	b = quicvarint.Append(b, typ)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	b = quicvarint.Append(b, uint64(f.FinalSize))
	if f.ReliableSize > 0 {
		b = quicvarint.Append(b, uint64(f.ReliableSize))
	}
	return b, nil
}

// Length of a written frame
func (f *ResetStreamFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(uint64(f.StreamID)) + quicvarint.Len(uint64(f.ErrorCode)) + quicvarint.Len(uint64(f.FinalSize))
}
