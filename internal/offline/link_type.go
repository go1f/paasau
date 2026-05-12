package offline

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func readLinkType(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	header := make([]byte, 24)
	if _, err := io.ReadFull(file, header); err != nil {
		return 0, err
	}

	switch {
	case header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1:
		return int(binary.LittleEndian.Uint32(header[20:24])), nil
	case header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1:
		return int(binary.LittleEndian.Uint32(header[20:24])), nil
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4:
		return int(binary.BigEndian.Uint32(header[20:24])), nil
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d:
		return int(binary.BigEndian.Uint32(header[20:24])), nil
	default:
		return 0, fmt.Errorf("unsupported pcap header magic: % x", header[0:4])
	}
}
