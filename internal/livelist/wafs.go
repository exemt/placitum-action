package livelist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	packVersion = 1

	kindSnapshot = 1
	kindPackage  = 2

	typeCIDR   = 1
	typeString = 2

	flagReasons = 1

	recAdd    = 1
	recRemove = 2

	packHeader = 52
	packMagic  = "WAFS"
)

var (
	errPackMagic   = errors.New("not a WAFS object")
	errPackVersion = errors.New("unsupported WAFS version")
	errPackShort   = errors.New("truncated WAFS object")
)

type packHead struct {
	kind  uint8
	typ   uint8
	flags uint8
	epoch uint64
	seq   uint64
	hash  uint64
	key   Key
	count uint32
}

type packRecord struct {
	op     uint8
	prefix netip.Prefix
	value  string
	exp    int64
	reason string
}

func prefixMaterial(p netip.Prefix) []byte {
	if p.Addr().Is4() {
		b := p.Addr().As4()

		return append([]byte{4, byte(p.Bits())}, b[:]...)
	}

	b := p.Addr().As16()

	return append([]byte{6, byte(p.Bits())}, b[:]...)
}

func unpack(data []byte) (packHead, []packRecord, error) {
	var head packHead

	if len(data) < packHeader {
		return head, nil, errPackShort
	}

	if string(data[:4]) != packMagic {
		return head, nil, errPackMagic
	}

	if data[4] != packVersion {
		return head, nil, errPackVersion
	}

	head.kind = data[5]
	head.typ = data[6]
	head.flags = data[7]
	head.epoch = binary.LittleEndian.Uint64(data[8:])
	head.seq = binary.LittleEndian.Uint64(data[16:])
	head.hash = binary.LittleEndian.Uint64(data[24:])
	copy(head.key[:], data[32:48])
	head.count = binary.LittleEndian.Uint32(data[48:])

	recs := make([]packRecord, 0, head.count)
	pos := packHeader

	for i := uint32(0); i < head.count; i++ {
		var r packRecord

		if pos+1 > len(data) {
			return head, nil, errPackShort
		}

		r.op = data[pos]
		pos++

		switch head.typ {
		case typeCIDR:
			if pos+2 > len(data) {
				return head, nil, errPackShort
			}

			fam, bits := data[pos], int(data[pos+1])
			pos += 2

			switch fam {
			case 4:
				if pos+4+8 > len(data) {
					return head, nil, errPackShort
				}

				var b [4]byte
				copy(b[:], data[pos:pos+4])
				r.prefix = netip.PrefixFrom(netip.AddrFrom4(b), bits)
				pos += 4

			case 6:
				if pos+16+8 > len(data) {
					return head, nil, errPackShort
				}

				var b [16]byte
				copy(b[:], data[pos:pos+16])
				r.prefix = netip.PrefixFrom(netip.AddrFrom16(b), bits)
				pos += 16

			default:
				return head, nil, fmt.Errorf("address family %d", fam)
			}

		case typeString:
			if pos+2 > len(data) {
				return head, nil, errPackShort
			}

			n := int(binary.LittleEndian.Uint16(data[pos:]))
			pos += 2

			if pos+n+8 > len(data) {
				return head, nil, errPackShort
			}

			r.value = string(data[pos : pos+n])
			pos += n

		default:
			return head, nil, fmt.Errorf("set type %d", head.typ)
		}

		r.exp = int64(binary.LittleEndian.Uint64(data[pos:]))
		pos += 8

		if head.typ == typeString && head.flags&flagReasons != 0 {
			if pos+2 > len(data) {
				return head, nil, errPackShort
			}

			n := int(binary.LittleEndian.Uint16(data[pos:]))
			pos += 2

			if pos+n > len(data) {
				return head, nil, errPackShort
			}

			r.reason = string(data[pos : pos+n])
			pos += n
		}

		recs = append(recs, r)
	}

	return head, recs, nil
}
