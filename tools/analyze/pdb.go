package analyze

// Minimal reader for Microsoft PDB 7.0 files: enough to name functions and
// data for the decompiler. Layout references: LLVM "The PDB File Format" and
// Microsoft's microsoft-pdb sources (cvinfo.h). All integers little-endian.
//
// A PDB is an MSF container: fixed-size blocks, a stream directory, and
// numbered streams. Streams used here:
//   1  PDB info (signature, age, GUID -- matched against the PE's RSDS record)
//   3  DBI (module list and the symbol record stream index)
//   n  each module's symbol stream (S_GPROC32 etc. with qualified names)
//   n  the symbol record stream (S_PUB32 publics, S_GDATA32 globals)

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var msfMagic = []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")

// maxPDBStream bounds one stream read; type and symbol streams of very large
// programs are tens of MB, a corrupt size field must not allocate gigabytes.
const maxPDBStream = 1 << 30

type pdbFile struct {
	f         *os.File
	blockSize uint32
	sizes     []uint32
	blocks    [][]uint32
}

func openPDB(path string) (*pdbFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	p, err := readMSF(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func (p *pdbFile) Close() error { return p.f.Close() }

func readMSF(f *os.File) (*pdbFile, error) {
	hdr := make([]byte, 56)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("not a PDB: %w", err)
	}
	if !bytes.Equal(hdr[:32], msfMagic) {
		return nil, errors.New("not a PDB 7.0 (MSF) file")
	}
	le := binary.LittleEndian
	p := &pdbFile{f: f, blockSize: le.Uint32(hdr[32:])}
	numBlocks := le.Uint32(hdr[40:])
	dirBytes := le.Uint32(hdr[44:])
	blockMapAddr := le.Uint32(hdr[52:])
	switch p.blockSize {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768:
	default:
		return nil, fmt.Errorf("unsupported MSF block size %d", p.blockSize)
	}
	if dirBytes == 0 || dirBytes > maxPDBStream || blockMapAddr >= numBlocks {
		return nil, errors.New("corrupt MSF directory")
	}
	// The block map lists the blocks that hold the stream directory.
	nDirBlocks := (dirBytes + p.blockSize - 1) / p.blockSize
	mapBuf := make([]byte, nDirBlocks*4)
	if _, err := f.ReadAt(mapBuf, int64(blockMapAddr)*int64(p.blockSize)); err != nil {
		return nil, fmt.Errorf("MSF block map: %w", err)
	}
	dirBlocks := make([]uint32, nDirBlocks)
	for i := range dirBlocks {
		dirBlocks[i] = le.Uint32(mapBuf[i*4:])
	}
	dir, err := p.readBlocks(dirBlocks, dirBytes)
	if err != nil {
		return nil, fmt.Errorf("MSF directory: %w", err)
	}

	if len(dir) < 4 {
		return nil, errors.New("corrupt MSF directory")
	}
	n := le.Uint32(dir)
	if uint64(n)*4+4 > uint64(len(dir)) {
		return nil, errors.New("corrupt MSF stream count")
	}
	p.sizes = make([]uint32, n)
	for i := range p.sizes {
		p.sizes[i] = le.Uint32(dir[4+i*4:])
	}
	pos := 4 + int(n)*4
	p.blocks = make([][]uint32, n)
	for i, size := range p.sizes {
		if size == 0xffffffff { // deleted stream
			p.sizes[i] = 0
			continue
		}
		cnt := int((size + p.blockSize - 1) / p.blockSize)
		if pos+cnt*4 > len(dir) {
			return nil, errors.New("corrupt MSF stream block list")
		}
		bl := make([]uint32, cnt)
		for j := range bl {
			bl[j] = le.Uint32(dir[pos+j*4:])
		}
		p.blocks[i] = bl
		pos += cnt * 4
	}
	return p, nil
}

func (p *pdbFile) readBlocks(blocks []uint32, size uint32) ([]byte, error) {
	if size > maxPDBStream {
		return nil, fmt.Errorf("stream of %d bytes exceeds the %d-byte limit", size, maxPDBStream)
	}
	out := make([]byte, size)
	for i, b := range blocks {
		lo := uint32(i) * p.blockSize
		if lo >= size {
			break
		}
		hi := min(lo+p.blockSize, size)
		if _, err := p.f.ReadAt(out[lo:hi], int64(b)*int64(p.blockSize)); err != nil && err != io.EOF {
			return nil, err
		}
	}
	return out, nil
}

// stream returns the whole content of stream i (nil for a missing stream).
func (p *pdbFile) stream(i int) ([]byte, error) {
	if i < 0 || i >= len(p.sizes) || p.sizes[i] == 0 {
		return nil, nil
	}
	return p.readBlocks(p.blocks[i], p.sizes[i])
}

// pdbInfo is the identity a PE's RSDS debug record must match.
type pdbInfo struct {
	age  uint32
	guid [16]byte
}

func (p *pdbFile) info() (pdbInfo, error) {
	s, err := p.stream(1)
	if err != nil {
		return pdbInfo{}, err
	}
	if len(s) < 28 {
		return pdbInfo{}, errors.New("PDB info stream too short")
	}
	var in pdbInfo
	in.age = binary.LittleEndian.Uint32(s[8:])
	copy(in.guid[:], s[12:28])
	return in, nil
}

// CodeView symbol kinds used here (cvinfo.h SYM_ENUM_e).
const (
	cvSLData32    = 0x110c
	cvSGData32    = 0x110d
	cvSPub32      = 0x110e
	cvSLProc32    = 0x110f
	cvSGProc32    = 0x1110
	cvSLProc32ID  = 0x1146
	cvSGProc32ID  = 0x1147
	cvPubFunction = 0x2 // CV_PUBSYMFLAGS fFunction
)

// pdbSymbol is a named address from the PDB: segment is the 1-based PE
// section index, offset is relative to that section.
type pdbSymbol struct {
	name     string
	segment  uint16
	offset   uint32
	function bool
	typeIdx  uint32 // procedure type (TPI) for procs, data type for globals
	size     uint32 // code size for procs
}

// pdbSymbols reads procedure symbols from every module stream and publics
// and global data from the symbol record stream.
type pdbSymbols struct {
	procs   []pdbSymbol // S_GPROC32/S_LPROC32: qualified, undecorated names
	publics []pdbSymbol // S_PUB32: decorated linker names
	globals []pdbSymbol // S_GDATA32/S_LDATA32
	modules int
}

func (p *pdbFile) symbols() (*pdbSymbols, error) {
	dbi, err := p.stream(3)
	if err != nil {
		return nil, err
	}
	if len(dbi) < 64 {
		return nil, errors.New("PDB has no DBI stream")
	}
	le := binary.LittleEndian
	symRecStream := int(le.Uint16(dbi[20:]))
	modInfoSize := int(int32(le.Uint32(dbi[24:])))
	if modInfoSize < 0 || 64+modInfoSize > len(dbi) {
		return nil, errors.New("corrupt DBI module info size")
	}
	out := &pdbSymbols{}

	// Module info entries: fixed 64 bytes, then module and object names,
	// padded to 4.
	mods := dbi[64 : 64+modInfoSize]
	for pos := 0; pos+64 <= len(mods); {
		modStream := int(le.Uint16(mods[pos+34:]))
		symBytes := le.Uint32(mods[pos+36:])
		nameEnd := pos + 64
		for k := 0; k < 2; k++ { // ModuleName, ObjFileName
			i := bytes.IndexByte(mods[nameEnd:], 0)
			if i < 0 {
				nameEnd = len(mods)
				break
			}
			nameEnd += i + 1
		}
		pos = (nameEnd + 3) &^ 3
		out.modules++
		if modStream == 0xffff || symBytes <= 4 {
			continue
		}
		s, err := p.stream(modStream)
		if err != nil || len(s) < int(symBytes) {
			continue
		}
		// The module stream starts with a 4-byte signature (CV_SIGNATURE_C13).
		walkCVSymbols(s[4:symBytes], func(kind uint16, rec []byte) {
			switch kind {
			case cvSGProc32, cvSLProc32, cvSGProc32ID, cvSLProc32ID:
				if len(rec) < 36 {
					return
				}
				out.procs = append(out.procs, pdbSymbol{
					name: cString(rec[35:]), size: le.Uint32(rec[12:]), typeIdx: le.Uint32(rec[24:]),
					offset: le.Uint32(rec[28:]), segment: le.Uint16(rec[32:]), function: true,
				})
			}
		})
	}

	if s, err := p.stream(symRecStream); err == nil && s != nil {
		walkCVSymbols(s, func(kind uint16, rec []byte) {
			switch kind {
			case cvSPub32:
				if len(rec) < 10 {
					return
				}
				out.publics = append(out.publics, pdbSymbol{
					name: cString(rec[10:]), offset: le.Uint32(rec[4:]), segment: le.Uint16(rec[8:]),
					function: le.Uint32(rec)&cvPubFunction != 0,
				})
			case cvSGData32, cvSLData32:
				if len(rec) < 10 {
					return
				}
				out.globals = append(out.globals, pdbSymbol{
					name: cString(rec[10:]), typeIdx: le.Uint32(rec), offset: le.Uint32(rec[4:]), segment: le.Uint16(rec[8:]),
				})
			}
		})
	}
	return out, nil
}

// walkCVSymbols calls fn for each CodeView symbol record (kind, payload after
// the kind field). Records are [u16 length][u16 kind][length-2 bytes].
func walkCVSymbols(b []byte, fn func(kind uint16, rec []byte)) {
	for pos := 0; pos+4 <= len(b); {
		n := int(binary.LittleEndian.Uint16(b[pos:]))
		if n < 2 || pos+2+n > len(b) {
			return
		}
		fn(binary.LittleEndian.Uint16(b[pos+2:]), b[pos+4:pos+2+n])
		pos += 2 + n
	}
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
