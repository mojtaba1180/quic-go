package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RELIABLE_RESET_STREAM frame", func() {
	Context("when parsing RESET_STREAM", func() {
		It("accepts sample frame", func() {
			data := []byte{0x4}
			data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
			data = append(data, encodeVarInt(0x1337)...)      // error code
			data = append(data, encodeVarInt(0x987654321)...) // final size
			b := bytes.NewReader(data)
			frame, err := parseResetStreamFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(frame.FinalSize).To(Equal(protocol.ByteCount(0x987654321)))
			Expect(frame.ErrorCode).To(Equal(qerr.StreamErrorCode(0x1337)))
			Expect(frame.ReliableSize).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x4}
			data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
			data = append(data, encodeVarInt(0x1337)...)      // error code
			data = append(data, encodeVarInt(0x987654321)...) // final size
			_, err := parseResetStreamFrame(bytes.NewReader(data), protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseResetStreamFrame(bytes.NewReader(data[0:i]), protocol.Version1)
				Expect(err).To(HaveOccurred())
			}
		})

		Context("when parsing RELIABLE_RESET_STREAM", func() {
			It("accepts sample frame", func() {
				data := []byte{0x72}
				data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
				data = append(data, encodeVarInt(0x1337)...)      // error code
				data = append(data, encodeVarInt(0x987654321)...) // final size
				data = append(data, encodeVarInt(0x42)...)        // reliable size
				b := bytes.NewReader(data)
				frame, err := parseResetStreamFrame(b, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.FinalSize).To(Equal(protocol.ByteCount(0x987654321)))
				Expect(frame.ErrorCode).To(Equal(qerr.StreamErrorCode(0x1337)))
				Expect(frame.ReliableSize).To(Equal(protocol.ByteCount(0x42)))
			})

			It("errors when the reliable size is larger than the final size", func() {
				data := []byte{0x72}
				data = append(data, encodeVarInt(0xdeadbeef)...) // stream ID
				data = append(data, encodeVarInt(0x1337)...)     // error code
				data = append(data, encodeVarInt(42)...)         // final size
				data = append(data, encodeVarInt(43)...)         // reliable size
				b := bytes.NewReader(data)
				_, err := parseResetStreamFrame(b, protocol.Version1)
				Expect(err).To(MatchError("RELIABLE_RESET_STREAM: reliable size can't be larger than final size (43 vs 42)"))
			})

			It("errors on EOFs", func() {
				data := []byte{0x72}
				data = append(data, encodeVarInt(0xdeadbeef)...)  // stream ID
				data = append(data, encodeVarInt(0x1337)...)      // error code
				data = append(data, encodeVarInt(0x987654321)...) // final size
				data = append(data, encodeVarInt(0x424242)...)    // reliable size
				_, err := parseResetStreamFrame(bytes.NewReader(data), protocol.Version1)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := parseResetStreamFrame(bytes.NewReader(data[0:i]), protocol.Version1)
					Expect(err).To(HaveOccurred())
				}
			})
		})
	})

	Context("when writing", func() {
		It("writes a RESET_STREAM frame", func() {
			frame := ResetStreamFrame{
				StreamID:  0x1337,
				FinalSize: 0x11223344decafbad,
				ErrorCode: 0xcafe,
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x4}
			expected = append(expected, encodeVarInt(0x1337)...)
			expected = append(expected, encodeVarInt(0xcafe)...)
			expected = append(expected, encodeVarInt(0x11223344decafbad)...)
			Expect(b).To(Equal(expected))
		})

		It("writes a RELIABLE_RESET_STREAM frame", func() {
			frame := ResetStreamFrame{
				StreamID:     0x1337,
				FinalSize:    0x11223344decafbad,
				ErrorCode:    0xcafe,
				ReliableSize: 0x42,
			}
			b, err := frame.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := append([]byte{}, encodeVarInt(0x72)...)
			expected = append(expected, encodeVarInt(0x1337)...)
			expected = append(expected, encodeVarInt(0xcafe)...)
			expected = append(expected, encodeVarInt(0x11223344decafbad)...)
			expected = append(expected, encodeVarInt(0x42)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct length", func() {
			rst := ResetStreamFrame{
				StreamID:  0x1337,
				FinalSize: 0x1234567,
				ErrorCode: 0xde,
			}
			expectedLen := 1 + quicvarint.Len(0x1337) + quicvarint.Len(0x1234567) + 2
			Expect(rst.Length(protocol.Version1)).To(Equal(expectedLen))
		})
	})
})
