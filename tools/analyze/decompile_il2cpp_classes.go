package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// This optional export describes runtime layout, not a metadata version guess.
// Method IDs distinguish overloads; addresses remain exact strings on disk.
type il2cppClassExport struct {
	Version      int                  `json:"version"`
	BinaryHash   string               `json:"binary_sha256"`
	PointerSize  int32                `json:"pointer_size"`
	VTableOffset int32                `json:"vtable_offset"`
	Classes      []il2cppClassRecord  `json:"classes"`
	Methods      []il2cppMethodRecord `json:"methods"`
}

type il2cppClassRecord struct {
	ID     string              `json:"id"`
	Name   string              `json:"name"`
	Size   int32               `json:"size"`
	Fields []il2cppClassField  `json:"fields"`
	Slots  []il2cppVirtualSlot `json:"slots"`
}

type il2cppClassField struct {
	Name   string `json:"name"`
	Offset int32  `json:"offset"`
	Type   string `json:"type"`
}

type il2cppVirtualSlot struct {
	Index  int32  `json:"index"`
	Method string `json:"method"`
}

type il2cppMethodRecord struct {
	ID        string   `json:"id"`
	Owner     string   `json:"owner"`
	Addresses []string `json:"addresses"`
	Static    bool     `json:"static"`
	Ret       string   `json:"ret"`
	Params    []string `json:"params"`
}

func (m *il2cppMethodRecord) UnmarshalJSON(data []byte) error {
	type plain il2cppMethodRecord
	var wire struct {
		plain
		Static *bool `json:"static"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Static == nil {
		return fmt.Errorf("class method requires explicit static flag")
	}
	*m = il2cppMethodRecord(wire.plain)
	m.Static = *wire.Static
	return nil
}

type il2cppClasses struct {
	prefix  string
	offset  int32
	classes map[string]*il2cppClassRecord
	names   map[string]string
	methods map[string]*il2cppMethodRecord
	byVA    map[uint64]*il2cppMethodRecord
	cache   map[uint64]*pcode.HostFunction
}

func loadIL2CPPClasses(path string, idx *il2cppPrototypes) error {
	f, err := os.Open(filepath.Join(filepath.Dir(path), "il2cpp-types.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 128<<20 {
		return fmt.Errorf("il2cpp-types.json must be a regular file of at most 128 MiB")
	}
	hash := sha256.New()
	d := json.NewDecoder(io.TeeReader(io.LimitReader(f, (128<<20)+1), hash))
	var export il2cppClassExport
	if err := d.Decode(&export); err != nil {
		return fmt.Errorf("il2cpp-types.json: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("il2cpp-types.json: trailing data")
	}
	classes, err := indexIL2CPPClasses(&export, idx)
	if err != nil {
		return err
	}
	classes.prefix = "il2cpp:" + hex.EncodeToString(hash.Sum(nil)) + ":"
	idx.classes = classes
	return nil
}

func indexIL2CPPClasses(e *il2cppClassExport, idx *il2cppPrototypes) (*il2cppClasses, error) {
	decoded, err := hex.DecodeString(e.BinaryHash)
	if err != nil || len(decoded) != 32 || idx.binarySHA256 == "" || !strings.EqualFold(e.BinaryHash, idx.binarySHA256) {
		return nil, fmt.Errorf("il2cpp-types.json requires matching signature and binary SHA-256 headers")
	}
	if e.Version != 1 || e.PointerSize != 8 || e.VTableOffset < 16 || e.VTableOffset > 65536 || e.VTableOffset%8 != 0 || len(e.Classes) > 100000 || len(e.Methods) > maxIL2CPPMethods {
		return nil, fmt.Errorf("il2cpp-types.json: unsupported layout or record limit")
	}
	c := &il2cppClasses{offset: e.VTableOffset, classes: map[string]*il2cppClassRecord{}, names: map[string]string{}, methods: map[string]*il2cppMethodRecord{}, byVA: map[uint64]*il2cppMethodRecord{}, cache: map[uint64]*pcode.HostFunction{}}
	for i := range e.Classes {
		r := &e.Classes[i]
		if r.ID == "" || len(r.ID) > 128 || r.Name == "" || len(r.Name) > 4096 || r.Size < 16 || r.Size > 1<<20 || len(r.Fields) > 4096 || len(r.Slots) > 4096 || c.classes[r.ID] != nil {
			return nil, fmt.Errorf("il2cpp-types.json: invalid or duplicate class")
		}
		c.classes[r.ID] = r
		if _, exists := c.names[r.Name]; exists {
			c.names[r.Name] = "" // ambiguous names never select an arbitrary type
		} else {
			c.names[r.Name] = r.ID
		}
		seen := map[int32]bool{}
		for _, f := range r.Fields {
			if len(f.Name) > 4096 || len(f.Type) > 4096 {
				return nil, fmt.Errorf("il2cpp-types.json: field exceeds name/type limit")
			}
		}
		for _, s := range r.Slots {
			if s.Index < 0 || s.Index >= 4096 || seen[s.Index] || s.Method == "" {
				return nil, fmt.Errorf("il2cpp-types.json: invalid or duplicate slot")
			}
			seen[s.Index] = true
		}
	}
	for i := range e.Methods {
		m := &e.Methods[i]
		if m.ID == "" || len(m.ID) > 128 || m.Owner == "" || len(m.Owner) > 128 || m.Ret == "" || len(m.Ret) > 4096 || c.methods[m.ID] != nil || len(m.Params) > 254 || len(m.Addresses) > 65536 {
			return nil, fmt.Errorf("il2cpp-types.json: invalid or duplicate method")
		}
		for _, token := range m.Params {
			if token == "" || len(token) > 4096 || strings.Contains(token, ",") {
				return nil, fmt.Errorf("il2cpp-types.json: invalid managed parameter token")
			}
		}
		c.methods[m.ID] = m
		q := il2cppTSVPrototype(m.Static, m.Ret, strings.Join(m.Params, ","), nil)
		for _, address := range m.Addresses {
			va, err := il2cppRVA([]byte(address))
			if err != nil {
				return nil, err
			}
			// Only decorate an existing, unambiguous locked prototype. This file
			// cannot introduce code addresses or replace an ABI disagreement.
			p := idx.methods[va]
			if p != nil && (q == nil || p.abi != q.abi) {
				return nil, fmt.Errorf("il2cpp-types.json contradicts a locked method signature")
			}
			if p == nil || q == nil || p.abi != q.abi {
				c.byVA[va] = nil
				continue
			}
			if previous, exists := c.byVA[va]; exists && (previous == nil || previous.Owner != m.Owner || previous.Static != m.Static || previous.Ret != m.Ret || strings.Join(previous.Params, ",") != strings.Join(m.Params, ",")) {
				c.byVA[va] = nil
			} else if !exists {
				c.byVA[va] = m
			}
		}
	}
	for _, r := range c.classes {
		for _, s := range r.Slots {
			if c.methods[s.Method] == nil {
				return nil, fmt.Errorf("il2cpp-types.json: slot references a missing method ID")
			}
		}
	}
	return c, nil
}

// Build only the graph needed by this requested prototype. A per-root identity
// keeps bounded/opaque leaves from poisoning later, independently built types.
// The core serializes decompilation in a worker, as for its debug type cache.
func (c *il2cppClasses) decorate(va uint64, base pcode.HostFunction) pcode.HostFunction {
	if cached, ok := c.cache[va]; ok {
		return *cached
	}
	m := c.byVA[va]
	if m == nil {
		return base
	}
	b := &il2cppClassBuilder{source: c, prefix: c.prefix + strconv.FormatUint(va, 16) + ":", objects: map[string]*pcode.HostTypeDesc{}}
	base.Params = append([]pcode.HostParam(nil), base.Params...)
	start := 0
	if !m.Static {
		if obj := b.object(m.Owner, 0); obj != nil && len(base.Params) > 0 {
			base.Params[0].Type = pcode.ResolveHostType(il2cppClassPointer(obj))
		}
		start = 1
	}
	for i, token := range m.Params {
		if start+i < len(base.Params) {
			if t := b.reference(token, 0); t != nil {
				base.Params[start+i].Type = pcode.ResolveHostType(t)
			}
		}
	}
	if base.Output != nil && base.OutputLocked {
		if t := b.reference(m.Ret, 0); t != nil {
			out := *base.Output
			out.Type = pcode.ResolveHostType(t)
			base.Output = &out
		}
	}
	c.cache[va] = &base
	return base
}

type il2cppClassBuilder struct {
	source  *il2cppClasses
	prefix  string
	objects map[string]*pcode.HostTypeDesc
}

func il2cppClassPointer(elem *pcode.HostTypeDesc) *pcode.HostTypeDesc {
	return &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: elem}
}

func il2cppClassName(s string) string {
	var out strings.Builder
	for _, r := range s {
		if out.Len() >= 80 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return "IL_" + out.String()
}

func (b *il2cppClassBuilder) reference(token string, depth int) *pcode.HostTypeDesc {
	if !strings.HasPrefix(token, "ref:") {
		return nil
	}
	name, err := url.PathUnescape(token[4:])
	if err != nil {
		return nil
	}
	if obj := b.object(b.source.names[name], depth); obj != nil {
		return il2cppClassPointer(obj)
	}
	return nil
}

func (b *il2cppClassBuilder) object(id string, depth int) *pcode.HostTypeDesc {
	if obj := b.objects[id]; obj != nil {
		return obj
	}
	r := b.source.classes[id]
	if r == nil || depth > 3 || len(b.objects) >= 64 {
		return nil
	}
	name := il2cppClassName(r.Name) + "_" + il2cppClassName(id)
	obj := &pcode.HostTypeDesc{Meta: "struct", Name: name + "_o", ID: b.prefix + id + ":o", Size: r.Size}
	b.objects[id] = obj
	cls := &pcode.HostTypeDesc{Meta: "struct", Name: name + "_c", ID: b.prefix + id + ":c", Size: b.source.offset}
	obj.Fields = append(obj.Fields, pcode.HostFieldDesc{Name: "klass", Type: il2cppClassPointer(cls)})
	var fields []pcode.HostFieldDesc
	for i, f := range r.Fields {
		t := b.reference(f.Type, depth+1)
		if t == nil {
			t, _ = il2cppClassToken(f.Type, false, false)
		}
		if t != nil && t.Meta != "void" && f.Offset >= 16 && t.Size > 0 && int64(f.Offset)+int64(t.Size) <= int64(r.Size) {
			fields = append(fields, pcode.HostFieldDesc{Name: il2cppClassName(f.Name) + "_" + strconv.Itoa(i), Offset: f.Offset, Type: t})
		}
	}
	// Explicit-layout unions and duplicate inherited fields must not select an
	// arbitrary pointer type. Drop the entire overlapping interval group.
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })
	for i := 0; i < len(fields); {
		j, end := i+1, fields[i].Offset+fields[i].Type.Size
		for j < len(fields) && fields[j].Offset < end {
			if next := fields[j].Offset + fields[j].Type.Size; next > end {
				end = next
			}
			j++
		}
		if j == i+1 {
			obj.Fields = append(obj.Fields, fields[i])
		}
		i = j
	}
	for _, s := range r.Slots {
		if end := b.source.offset + (s.Index+1)*16; end > cls.Size {
			cls.Size = end
		}
		m := b.source.methods[s.Method]
		if m == nil || m.Static {
			continue
		}
		ret, ok := il2cppClassToken(m.Ret, true, true)
		if !ok {
			continue // hidden return buffers and unknown signatures stay inferred
		}
		cp := &pcode.HostCodeProto{ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutLocked: true, Ret: ret, Params: []*pcode.HostTypeDesc{il2cppClassPointer(obj)}}
		for _, token := range m.Params {
			t, valid := il2cppClassToken(token, false, true)
			if !valid {
				ok = false
				break
			}
			cp.Params = append(cp.Params, t)
		}
		if !ok {
			continue
		}
		cp.Params = append(cp.Params, il2cppClassPointer(&pcode.HostTypeDesc{Meta: "void"}))
		offset := b.source.offset + s.Index*16
		codeID := sha256.Sum256([]byte(b.prefix + id + ":" + strconv.Itoa(int(s.Index))))
		fn := &pcode.HostTypeDesc{Meta: "code", Name: name + "_slot_" + strconv.Itoa(int(s.Index)) + "_" + hex.EncodeToString(codeID[:]) + "_fn", Size: 1, Proto: cp}
		cls.Fields = append(cls.Fields, pcode.HostFieldDesc{Name: "slot_" + strconv.Itoa(int(s.Index)) + "_methodPtr", Offset: offset, Type: il2cppClassPointer(fn)}, pcode.HostFieldDesc{Name: "slot_" + strconv.Itoa(int(s.Index)) + "_method", Offset: offset + 8, Type: il2cppClassPointer(&pcode.HostTypeDesc{Meta: "void"})})
		if offset+16 > cls.Size {
			cls.Size = offset + 16
		}
	}
	return obj
}

func il2cppClassToken(token string, output, abi bool) (*pcode.HostTypeDesc, bool) {
	types := newIL2CPPTypes("")
	c := il2cppTSVCType(token, nil, types)
	if c == "" {
		return nil, false
	}
	d, aggregate := types.ctype(c)
	if d == nil || !output && d.Meta == "void" {
		return nil, false
	}
	if aggregate && abi {
		if il2cppRegisterAggregate(d.Size) {
			d = &pcode.HostTypeDesc{Meta: "uint", Size: d.Size}
		} else if output {
			return nil, false
		} else {
			d = il2cppClassPointer(&pcode.HostTypeDesc{Meta: "void"})
		}
	}
	return d, true
}
