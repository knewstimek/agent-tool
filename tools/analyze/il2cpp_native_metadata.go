package analyze

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

// The on-disk v39 layout is specified by the matching runtime metadata reader.
// No managed runtime or third-party dumper is executed by this implementation.
type il2cppNativeTable struct {
	data  []byte
	count int
}
type il2cppNativeMetadata struct {
	tables  [31]il2cppNativeTable
	types   []il2cppNativeTypeDef
	methods []il2cppNativeMethod
	fields  []il2cppNativeField
	params  []int
	images  []il2cppNativeAssembly
}
type il2cppNativeTypeDef struct {
	name, namespace                      string
	byval, declaring, parent, generic    int
	flags, bits                          uint32
	fieldStart, methodStart, vtableStart int
	fieldCount, methodCount, vtableCount int
}
type il2cppNativeMethod struct {
	name                                                string
	owner, ret, parameterStart, parameterCount, generic int
	token                                               uint32
	flags                                               uint16
}
type il2cppNativeField struct {
	name       string
	nativeType int
}
type il2cppNativeAssembly struct {
	name         string
	start, count int
}

func readIL2CPPBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 512<<20 {
		return nil, fmt.Errorf("IL2CPP metadata must be a regular file of at most 512 MiB")
	}
	d, err := io.ReadAll(io.LimitReader(f, (512<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(d) > 512<<20 {
		return nil, fmt.Errorf("IL2CPP metadata grew beyond size limit")
	}
	return d, nil
}

func parseIL2CPPNativeMetadata(data []byte) (*il2cppNativeMetadata, error) {
	const headerSize = 8 + 31*12
	if len(data) < headerSize || binary.LittleEndian.Uint32(data) != 0xfab11baf {
		return nil, fmt.Errorf("invalid or truncated IL2CPP metadata header")
	}
	if version := binary.LittleEndian.Uint32(data[4:]); version != 39 {
		return nil, fmt.Errorf("native IL2CPP extraction supports metadata v39; version %d requires an external signature export", version)
	}
	m := &il2cppNativeMetadata{}
	for i := range m.tables {
		h := data[8+i*12:]
		off, size, n := uint64(binary.LittleEndian.Uint32(h)), uint64(binary.LittleEndian.Uint32(h[4:])), uint64(binary.LittleEndian.Uint32(h[8:]))
		recordTable := i == 5 || i == 10 || i == 11 || i == 14 || i == 17 || i == 19 || i == 20
		if n > 512<<20 || recordTable && n > maxIL2CPPMethods || off > uint64(len(data)) || size > uint64(len(data))-off || size > 0 && off < headerSize {
			return nil, fmt.Errorf("IL2CPP metadata section %d exceeds bounds", i)
		}
		m.tables[i] = il2cppNativeTable{data: data[off : off+size], count: int(n)}
	}
	if m.tables[19].count == 0 || m.tables[5].count == 0 {
		return nil, fmt.Errorf("IL2CPP metadata has no types/methods")
	}
	return m, nil
}

func (m *il2cppNativeMetadata) text(index int) (string, error) {
	d := m.tables[2].data
	if index < 0 || index >= len(d) {
		return "", fmt.Errorf("invalid IL2CPP string index")
	}
	end := bytes.IndexByte(d[index:min(len(d), index+65536)], 0)
	if end < 0 || !utf8.Valid(d[index:index+end]) {
		return "", fmt.Errorf("invalid or oversized IL2CPP identifier")
	}
	return string(d[index : index+end]), nil
}

func il2cppIndexWidth(count int) int {
	if count < 256 {
		return 1
	}
	if count < 65536 {
		return 2
	}
	return 4
}

type il2cppNativeCursor struct {
	data []byte
	off  int
	err  error
}

func (c *il2cppNativeCursor) uint(size int) uint32 {
	if c.err != nil {
		return 0
	}
	if size < 1 || size > 4 || size == 3 || size > len(c.data)-c.off {
		c.err = fmt.Errorf("truncated IL2CPP metadata record")
		return 0
	}
	var n uint32
	for i := 0; i < size; i++ {
		n |= uint32(c.data[c.off+i]) << uint(8*i)
	}
	c.off += size
	return n
}
func (c *il2cppNativeCursor) index(size int) int {
	n := c.uint(size)
	if n == uint32((uint64(1)<<uint(size*8))-1) {
		return -1
	}
	return int(n)
}

func (m *il2cppNativeMetadata) decode(typesCount int) error {
	tw, dw, gw, pw := il2cppIndexWidth(typesCount), il2cppIndexWidth(m.tables[19].count), il2cppIndexWidth(m.tables[14].count), il2cppIndexWidth(m.tables[10].count)
	readRows := func(table, size int, read func(*il2cppNativeCursor) error) error {
		s := m.tables[table]
		if size < 1 || len(s.data) != s.count*size {
			return fmt.Errorf("IL2CPP metadata section %d record size mismatch", table)
		}
		for i := 0; i < s.count; i++ {
			c := &il2cppNativeCursor{data: s.data[i*size : (i+1)*size]}
			if err := read(c); err != nil {
				return err
			}
			if c.err != nil {
				return c.err
			}
			if c.off != size {
				return fmt.Errorf("IL2CPP record layout mismatch in section %d", table)
			}
		}
		return nil
	}
	m.types = make([]il2cppNativeTypeDef, 0, m.tables[19].count)
	err := readRows(19, 68+3*tw+gw, func(c *il2cppNativeCursor) error {
		var r il2cppNativeTypeDef
		var e error
		r.name, e = m.text(c.index(4))
		if e != nil {
			return e
		}
		r.namespace, e = m.text(c.index(4))
		if e != nil {
			return e
		}
		r.byval = c.index(tw)
		r.declaring = c.index(tw)
		r.parent = c.index(tw)
		r.generic = c.index(gw)
		r.flags = c.uint(4)
		r.fieldStart = c.index(4)
		r.methodStart = c.index(4)
		c.uint(4)
		c.uint(4)
		c.uint(4)
		c.uint(4)
		r.vtableStart = c.index(4)
		c.uint(4)
		r.methodCount = int(c.uint(2))
		c.uint(2)
		r.fieldCount = int(c.uint(2))
		c.uint(2)
		c.uint(2)
		r.vtableCount = int(c.uint(2))
		c.uint(2)
		c.uint(2)
		r.bits = c.uint(4)
		c.uint(4)
		if !il2cppNativeRange(r.fieldStart, r.fieldCount, m.tables[11].count) || !il2cppNativeRange(r.methodStart, r.methodCount, m.tables[5].count) || !il2cppNativeRange(r.vtableStart, r.vtableCount, m.tables[17].count) {
			return fmt.Errorf("IL2CPP type member range exceeds metadata")
		}
		m.types = append(m.types, r)
		return nil
	})
	if err != nil {
		return err
	}
	m.methods = make([]il2cppNativeMethod, 0, m.tables[5].count)
	err = readRows(5, 20+dw+tw+pw+gw, func(c *il2cppNativeCursor) error {
		var r il2cppNativeMethod
		var e error
		r.name, e = m.text(c.index(4))
		if e != nil {
			return e
		}
		r.owner = c.index(dw)
		r.ret = c.index(tw)
		c.uint(4)
		r.parameterStart = c.index(pw)
		r.generic = c.index(gw)
		r.token = c.uint(4)
		r.flags = uint16(c.uint(2))
		c.uint(2)
		c.uint(2)
		r.parameterCount = int(c.uint(2))
		if r.owner < 0 || r.owner >= len(m.types) || r.ret < 0 || r.ret >= typesCount || r.parameterCount > 254 || !il2cppNativeRange(r.parameterStart, r.parameterCount, m.tables[10].count) {
			return fmt.Errorf("IL2CPP method has an invalid owner/type/parameter range")
		}
		m.methods = append(m.methods, r)
		return nil
	})
	if err != nil {
		return err
	}
	m.params = make([]int, 0, m.tables[10].count)
	err = readRows(10, 8+tw, func(c *il2cppNativeCursor) error {
		if _, e := m.text(c.index(4)); e != nil {
			return e
		}
		c.uint(4)
		t := c.index(tw)
		if t < 0 || t >= typesCount {
			return fmt.Errorf("invalid IL2CPP parameter type")
		}
		m.params = append(m.params, t)
		return nil
	})
	if err != nil {
		return err
	}
	m.fields = make([]il2cppNativeField, 0, m.tables[11].count)
	err = readRows(11, 8+tw, func(c *il2cppNativeCursor) error {
		name, e := m.text(c.index(4))
		if e != nil {
			return e
		}
		t := c.index(tw)
		c.uint(4)
		if t < 0 || t >= typesCount {
			return fmt.Errorf("invalid IL2CPP field type")
		}
		m.fields = append(m.fields, il2cppNativeField{name, t})
		return nil
	})
	if err != nil {
		return err
	}
	err = readRows(20, 32+2*dw, func(c *il2cppNativeCursor) error {
		name, e := m.text(c.index(4))
		if e != nil {
			return e
		}
		c.uint(4)
		start := c.index(dw)
		n := int(c.uint(4))
		c.index(dw)
		c.uint(4)
		c.uint(4)
		c.uint(4)
		c.uint(4)
		c.uint(4)
		if !il2cppNativeRange(start, n, len(m.types)) {
			return fmt.Errorf("invalid IL2CPP assembly type range")
		}
		m.images = append(m.images, il2cppNativeAssembly{name, start, n})
		return nil
	})
	if err != nil {
		return err
	}
	return m.validateOwnership(typesCount)
}

func (m *il2cppNativeMetadata) validateOwnership(typesCount int) error {
	covered := make([]bool, len(m.types))
	for _, image := range m.images {
		for i := 0; i < image.count; i++ {
			index := image.start + i
			if covered[index] {
				return fmt.Errorf("overlapping IL2CPP image type ranges")
			}
			covered[index] = true
		}
	}
	methods := make([]bool, len(m.methods))
	for owner, td := range m.types {
		if !covered[owner] || td.byval < 0 || td.byval >= typesCount {
			return fmt.Errorf("unmapped IL2CPP type definition")
		}
		for i := 0; i < td.methodCount; i++ {
			index := td.methodStart + i
			if methods[index] || m.methods[index].owner != owner {
				return fmt.Errorf("inconsistent IL2CPP method ownership")
			}
			methods[index] = true
		}
	}
	for _, mapped := range methods {
		if !mapped {
			return fmt.Errorf("unmapped IL2CPP method definition")
		}
	}
	return nil
}

func il2cppNativeRange(start, count, total int) bool {
	return count == 0 && start >= -1 || start >= 0 && count >= 0 && start <= total && count <= total-start
}
