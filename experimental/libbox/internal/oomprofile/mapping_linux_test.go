package oomprofile

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseProcSelfMapsPreservesExecutableMetadata(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mapped binary with spaces")
	id := []byte{0x12, 0x34, 0xab, 0xcd}
	if err := os.WriteFile(file, elfNoteFixture(binary.LittleEndian, 2, id), 0o600); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf(`1000-2000 r-xp 00001000 00:00 17 %s (deleted)
2000-3000 r--p 00000000 00:00 17 %s
3000-4000 rwxp 00000020 00:00 0 [vdso]
4000-5000 r-xp 00000000 00:00 0
5000-6000 r-xp 00000000 00:00 0%s
invalid-7000 r-xp 00000000 00:00 1 /bad
7000-invalid r-xp 00000000 00:00 1 /bad
7000-8000 r-xp invalid 00:00 1 /bad
8000-9000 r-x 00000000 00:00 1 /bad
not-a-mapping
9000-a000 r-xp 00000000 00:00 17 /missing-without-final-newline`, file, file, "    ")
	var mappings []memMap
	parseProcSelfMaps([]byte(data), func(lo, hi, offset uint64, file, buildID string) {
		mappings = append(mappings, memMap{start: uintptr(lo), end: uintptr(hi), offset: offset,
			file: file, buildID: buildID})
	})
	want := []memMap{
		{start: 0x1000, end: 0x2000, offset: 0x1000, file: file, buildID: hex.EncodeToString(id)},
		{start: 0x3000, end: 0x4000, offset: 0x20, file: "[vdso]"},
		{start: 0x9000, end: 0xa000, file: "/missing-without-final-newline"},
	}
	if !reflect.DeepEqual(mappings, want) {
		t.Fatalf("mappings = %#v, want %#v", mappings, want)
	}
}

func TestELFBuildIDLayoutsAndInvalidInput(t *testing.T) {
	id := []byte{0x12, 0x34, 0xab, 0xcd, 0xef}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, class := range []byte{1, 2} {
			t.Run(fmt.Sprintf("%s/class%d", order, class), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "test.elf")
				fixture := elfNoteFixture(order, class, id)
				if err := os.WriteFile(path, fixture, 0o600); err != nil {
					t.Fatal(err)
				}
				if got, err := elfBuildID(path); err != nil || got != hex.EncodeToString(id) {
					t.Fatalf("BuildID = %q, %v", got, err)
				}
				for _, size := range []int{0, 63, 80, len(fixture) - 4} {
					if err := os.WriteFile(path, fixture[:size], 0o600); err != nil {
						t.Fatal(err)
					}
					if _, err := elfBuildID(path); err == nil {
						t.Fatalf("accepted truncated ELF of %d bytes", size)
					}
				}
			})
		}
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{"magic", func(b []byte) { b[0] = 0 }, errBadELF},
		{"class", func(b []byte) { b[4] = 0 }, errBadELF},
		{"byte-order", func(b []byte) { b[5] = 0 }, errBadELF},
		{"section-size", func(b []byte) { b[58] = 63 }, errBadELF},
		{"no-note", func(b []byte) { b[68] = 1 }, errNoBuildID},
		{"wrong-note-name", func(b []byte) { b[140] = 'X' }, errNoBuildID},
		{"wrong-note-type", func(b []byte) { b[136] = 1 }, errNoBuildID},
		{"oversized-description", func(b []byte) { binary.LittleEndian.PutUint32(b[132:], 257) }, errBadELF},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := elfNoteFixture(binary.LittleEndian, 2, id)
			test.mutate(fixture)
			path := filepath.Join(t.TempDir(), "bad.elf")
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := elfBuildID(path); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := elfBuildID(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
}

func elfNoteFixture(order binary.ByteOrder, class byte, id []byte) []byte {
	data := make([]byte, 144+((len(id)+3)&^3))
	copy(data, "\x7fELF")
	data[4], data[5] = class, 1
	if order == binary.BigEndian {
		data[5] = 2
	}
	const section, note = 64, 128
	if class == 1 {
		order.PutUint32(data[32:], section)
		order.PutUint16(data[46:], 40)
		order.PutUint16(data[48:], 1)
		order.PutUint32(data[section+16:], note)
		order.PutUint32(data[section+20:], uint32(len(data)-note))
	} else {
		order.PutUint64(data[40:], section)
		order.PutUint16(data[58:], 64)
		order.PutUint16(data[60:], 1)
		order.PutUint64(data[section+24:], note)
		order.PutUint64(data[section+32:], uint64(len(data)-note))
	}
	order.PutUint32(data[section+4:], 7)
	order.PutUint32(data[note:], 4)
	order.PutUint32(data[note+4:], uint32(len(id)))
	order.PutUint32(data[note+8:], 3)
	copy(data[note+12:], "GNU\x00")
	copy(data[note+16:], id)
	return data
}
