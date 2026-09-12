/*
 * SipHash-2-4 -- хеш записи набора.
 *
 * Хеш состава -- XOR хешей записей, и его сверяют зеркала на другом языке
 * (модуль на C). Поэтому функция задана до байта: SipHash-2-4 с 16-байтовым
 * ключом эпохи, вход -- материал записи (wafs.go): у адреса семейство, биты
 * и адрес под маской, у строки -- она сама. Ключ эпохи нужен не для
 * секретности, а чтобы записи с подобранными значениями (адреса из трафика
 * в бан-наборе) не могли сложиться в нужный XOR и спрятать расхождение.
 *
 * Реализация справочная (Aumasson, Bernstein), без ускорений: на записи
 * хеш считается один раз, а не на каждом запросе.
 */

package livelist

import "encoding/binary"

type Key [16]byte

func rotl(x uint64, b uint) uint64 { return (x << b) | (x >> (64 - b)) }

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = rotl(*v1, 13)
	*v1 ^= *v0
	*v0 = rotl(*v0, 32)
	*v2 += *v3
	*v3 = rotl(*v3, 16)
	*v3 ^= *v2
	*v0 += *v3
	*v3 = rotl(*v3, 21)
	*v3 ^= *v0
	*v2 += *v1
	*v1 = rotl(*v1, 17)
	*v1 ^= *v2
	*v2 = rotl(*v2, 32)
}

// SipHash считает SipHash-2-4 строки s под ключом k.
func SipHash(k Key, s string) uint64 { return SipHashBytes(k, []byte(s)) }

// SipHashBytes считает SipHash-2-4 байтов b под ключом k.
func SipHashBytes(k Key, b []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(k[0:8])
	k1 := binary.LittleEndian.Uint64(k[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	n := len(b)
	full := n - n%8

	for i := 0; i < full; i += 8 {
		m := binary.LittleEndian.Uint64(b[i : i+8])
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
	}

	var last uint64 = uint64(n) << 56

	for i := full; i < n; i++ {
		last |= uint64(b[i]) << (8 * uint(i-full))
	}

	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		sipRound(&v0, &v1, &v2, &v3)
	}

	return v0 ^ v1 ^ v2 ^ v3
}
