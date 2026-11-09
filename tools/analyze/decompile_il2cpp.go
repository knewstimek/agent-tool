package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/pcode"
)

const maxIL2CPPMethods = 1_000_000

var il2cppSignature = regexp.MustCompile(`^(.+?[\s*])([A-Za-z_][A-Za-z_0-9]*)\s*\(([^()]*)\)\s*;?$`)

type il2cppPrototype struct {
	function pcode.HostFunction
	abi      string
}

type il2cppPrototypes struct {
	path         string
	methods      map[uint64]*il2cppPrototype // nil permanently blocks an ambiguous entry
	locked       int
	skipped      int
	binarySHA256 string
	classes      *il2cppClasses
}

func il2cppScriptPath(binary, selected string) string {
	if selected == "none" {
		return ""
	}
	if selected != "" {
		return selected
	}
	jsonPath := filepath.Join(filepath.Dir(binary), "script.json")
	if _, err := os.Stat(jsonPath); err == nil {
		return jsonPath
	}
	tsvPath := filepath.Join(filepath.Dir(binary), "methodsigs.tsv")
	if _, err := os.Stat(tsvPath); err == nil {
		return tsvPath
	}
	return jsonPath
}

func il2cppSourceIdentity(binary, selected string) string {
	path := il2cppScriptPath(binary, selected)
	if path == "" {
		return "none"
	}
	return fmt.Sprintf("%q:%q:%q:%q:%q", path, fileIdentity(path), fileIdentity(filepath.Join(filepath.Dir(path), "il2cpp.h")), fileIdentity(filepath.Join(filepath.Dir(path), "sizes.tsv")), fileIdentity(filepath.Join(filepath.Dir(path), "il2cpp-types.json")))
}

func loadIL2CPPPrototypes(binary, selected string, bin *cgBinary) (*il2cppPrototypes, error) {
	path := il2cppScriptPath(binary, selected)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) && selected == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("IL2CPP signatures: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 512<<20 {
		return nil, fmt.Errorf("IL2CPP signatures must be a regular file of at most 512 MiB")
	}
	valid := func(rva uint64) bool {
		return rva <= math.MaxUint32 && rva <= math.MaxUint64-bin.imageBase && isInExecSection(bin.execSections, uint32(rva))
	}
	var idx *il2cppPrototypes
	if strings.EqualFold(filepath.Ext(path), ".tsv") {
		var sizes map[string]int32
		sizes, err = loadIL2CPPValueSizes(path)
		if err == nil {
			idx, err = parseIL2CPPMethodsTSV(io.LimitReader(f, (512<<20)+1), sizes, func(va uint64) bool {
				return va >= bin.imageBase && valid(va-bin.imageBase)
			})
		}
	} else {
		var types *il2cppTypes
		types, err = loadIL2CPPTypes(path)
		if err == nil {
			idx, err = parseIL2CPPScript(io.LimitReader(f, (512<<20)+1), bin.imageBase, types, valid)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("IL2CPP signatures: %w", err)
	}
	if idx.binarySHA256 != "" {
		binaryFile, err := os.Open(binary)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, binaryFile)
		_ = binaryFile.Close()
		if readErr != nil || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), idx.binarySHA256) {
			return nil, fmt.Errorf("IL2CPP signatures were exported for a different binary (SHA-256 mismatch)")
		}
	}
	if err := loadIL2CPPClasses(path, idx); err != nil {
		return nil, fmt.Errorf("IL2CPP classes: %w", err)
	}
	idx.path = path
	return idx, nil
}

func parseIL2CPPScript(r io.Reader, imageBase uint64, types *il2cppTypes, valid func(uint64) bool) (*il2cppPrototypes, error) {
	d := json.NewDecoder(r)
	d.UseNumber() // never round an RVA through float64
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, fmt.Errorf("expected a JSON object")
	}
	idx := &il2cppPrototypes{methods: map[uint64]*il2cppPrototype{}}
	found, count := false, 0
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		if key != "ScriptMethod" {
			if err := skipIL2CPPJSON(d, 0); err != nil {
				return nil, err
			}
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate ScriptMethod array")
		}
		found = true
		if token, err := d.Token(); err != nil || token != json.Delim('[') {
			return nil, fmt.Errorf("ScriptMethod must be an array")
		}
		for d.More() {
			count++
			if count > maxIL2CPPMethods {
				return nil, fmt.Errorf("ScriptMethod exceeds %d entries", maxIL2CPPMethods)
			}
			var method struct {
				Address   json.RawMessage
				Signature string
			}
			if err := d.Decode(&method); err != nil {
				return nil, err
			}
			rva, err := il2cppRVA(method.Address)
			if err != nil {
				return nil, err
			}
			if rva == 0 || rva > math.MaxUint64-imageBase || valid != nil && !valid(rva) {
				idx.skipped++
				continue
			}
			va := imageBase + rva
			idx.add(va, parseIL2CPPPrototype(method.Signature, types))
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	if !found {
		return nil, fmt.Errorf("ScriptMethod array is missing")
	}
	idx.finish()
	return idx, nil
}

func (idx *il2cppPrototypes) add(va uint64, proto *il2cppPrototype) {
	if previous, exists := idx.methods[va]; exists && (previous == nil || proto == nil || previous.abi != proto.abi) {
		idx.methods[va] = nil
	} else if !exists {
		idx.methods[va] = proto
	}
}

func (idx *il2cppPrototypes) finish() {
	for _, p := range idx.methods {
		if p == nil {
			idx.skipped++
		} else {
			idx.locked++
		}
	}
}

// Skip unrelated dumper arrays without retaining their string/metadata records.
func skipIL2CPPJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok {
		if delim != '[' && delim != '{' {
			return fmt.Errorf("unexpected JSON delimiter")
		}
		for d.More() {
			if delim == '{' {
				if _, err := d.Token(); err != nil {
					return err
				}
			}
			if err := skipIL2CPPJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func il2cppRVA(raw json.RawMessage) (uint64, error) {
	s := string(raw)
	if len(s) > 0 && s[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("invalid method Address")
		}
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s, base = s[2:], 16
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, fmt.Errorf("method Address must be an exact unsigned integer RVA")
	}
	return n, nil
}

func parseIL2CPPPrototype(signature string, types *il2cppTypes) *il2cppPrototype {
	if len(signature) > 65536 {
		return nil
	}
	m := il2cppSignature.FindStringSubmatch(strings.TrimSpace(signature))
	if m == nil {
		return nil
	}
	ret, aggregate := types.ctype(m[1])
	if ret == nil {
		return nil
	}
	p := &il2cppPrototype{function: pcode.HostFunction{ExtraPop: pcode.ExtrapopUnknown, InputLocked: true}}
	p.abi = il2cppTypeKey(ret)
	// Windows x64 passes only 1/2/4/8-byte POD aggregates in integer slots.
	// Other return aggregates need a hidden return buffer: leave output unknown.
	if !aggregate || il2cppRegisterAggregate(ret.Size) {
		if aggregate {
			ret = &pcode.HostTypeDesc{Meta: "uint", Size: ret.Size}
		}
		t := pcode.ResolveHostType(ret)
		if t == nil {
			return nil
		}
		p.function.Output, p.function.OutputLocked = &pcode.HostParam{Type: t, Size: t.Size()}, true
	}
	args := strings.TrimSpace(m[3])
	if args == "" || args == "void" {
		return p
	}
	parts := strings.Split(args, ",")
	if len(parts) > 256 {
		return nil
	}
	for _, arg := range parts {
		arg = strings.TrimSpace(arg)
		field := il2cppField.FindStringSubmatch(arg)
		if field == nil || field[3] != "" {
			return nil
		}
		d, aggregate := types.ctype(field[1])
		if d == nil || d.Meta == "void" {
			return nil
		}
		// Record the original aggregate size too: differing generic signatures
		// cannot become equivalent merely because both use an indirect slot.
		p.abi += ";" + il2cppTypeKey(d)
		if aggregate {
			if il2cppRegisterAggregate(d.Size) {
				d = &pcode.HostTypeDesc{Meta: "uint", Size: d.Size}
			} else {
				d = &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: &pcode.HostTypeDesc{Meta: "void"}}
			}
		}
		t := pcode.ResolveHostType(d)
		if t == nil {
			return nil
		}
		this := field[2] == "__this"
		if this {
			if len(p.function.Params) != 0 || d.Meta != "ptr" {
				return nil
			}
			p.abi += ":this"
		}
		p.function.Params = append(p.function.Params, pcode.HostParam{Name: field[2], Size: t.Size(), Type: t, ThisPtr: this})
	}
	return p
}

func il2cppRegisterAggregate(size int32) bool {
	return size == 1 || size == 2 || size == 4 || size == 8
}

func il2cppTypeKey(d *pcode.HostTypeDesc) string {
	key := fmt.Sprintf("%s:%d", d.Meta, d.Size)
	if d.Elem != nil {
		key += "(" + il2cppTypeKey(d.Elem) + ")"
	}
	return key
}

func (s *il2cppPrototypes) prototype(va uint64) *pcode.HostFunction {
	if s == nil || s.methods[va] == nil {
		return nil
	}
	p := s.methods[va].function
	if s.classes != nil {
		p = s.classes.decorate(va, p)
	}
	p.Params = append([]pcode.HostParam(nil), p.Params...)
	if p.Output != nil {
		out := *p.Output
		p.Output = &out
	}
	return &p
}
