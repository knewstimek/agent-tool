package analyze

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// methodsigs.tsv: VA, static (0/1), return token, comma-separated parameter
// tokens, diagnostic name. Names are never applied to the decompiler host.
// val:SIZE:NAME carries an exact payload size. val:NAME may instead use the
// dumper's sibling sizes.tsv. Percent-escape commas inside type names.
func parseIL2CPPMethodsTSV(r io.Reader, sizes map[string]int32, valid func(uint64) bool) (*il2cppPrototypes, error) {
	idx := &il2cppPrototypes{methods: map[uint64]*il2cppPrototype{}}
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 4096), 65536)
	row, count := 0, 0
	for scan.Scan() {
		row++
		line := strings.TrimSuffix(scan.Text(), "\r")
		if row == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		if hash, ok := strings.CutPrefix(line, "# binary_sha256="); ok {
			decoded, err := hex.DecodeString(hash)
			if err != nil || len(decoded) != 32 || idx.binarySHA256 != "" && !strings.EqualFold(idx.binarySHA256, hash) {
				return nil, fmt.Errorf("invalid or conflicting binary SHA-256 header")
			}
			idx.binarySHA256 = hash
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) == 5 && strings.EqualFold(cols[0], "VA") && strings.EqualFold(cols[1], "static") {
			continue
		}
		if len(cols) != 5 || cols[1] != "0" && cols[1] != "1" {
			return nil, fmt.Errorf("methodsigs.tsv row %d must contain VA, static (0/1), ret, params, name", row)
		}
		count++
		if count > maxIL2CPPMethods {
			return nil, fmt.Errorf("methodsigs.tsv exceeds %d entries", maxIL2CPPMethods)
		}
		va, err := il2cppRVA([]byte(cols[0]))
		if err != nil {
			return nil, fmt.Errorf("methodsigs.tsv row %d: %w", row, err)
		}
		if va == 0 || valid != nil && !valid(va) {
			idx.skipped++
			continue
		}
		idx.add(va, il2cppTSVPrototype(cols[1] == "1", cols[2], cols[3], sizes))
	}
	if err := scan.Err(); err != nil {
		return nil, fmt.Errorf("methodsigs.tsv: %w", err)
	}
	idx.finish()
	return idx, nil
}

func il2cppTSVPrototype(static bool, retToken, params string, sizes map[string]int32) *il2cppPrototype {
	types := newIL2CPPTypes("")
	ret := il2cppTSVCType(retToken, sizes, types)
	if ret == "" {
		return nil
	}
	args := make([]string, 0, 8)
	if !static {
		args = append(args, "void* __this")
	}
	if params != "" {
		parts := strings.Split(params, ",")
		if len(parts) > 254 {
			return nil
		}
		for i, token := range parts {
			t := il2cppTSVCType(token, sizes, types)
			if t == "" || t == "void" {
				return nil
			}
			args = append(args, fmt.Sprintf("%s arg_%d", t, i+1))
		}
	}
	args = append(args, "const MethodInfo* method")
	return parseIL2CPPPrototype(ret+" method("+strings.Join(args, ", ")+");", types)
}

func il2cppTSVCType(token string, sizes map[string]int32, types *il2cppTypes) string {
	if strings.HasPrefix(token, "ref:") || strings.HasPrefix(token, "ptr:") {
		if len(token) <= 4 {
			return ""
		}
		return "void*"
	}
	if strings.HasPrefix(token, "val:") {
		name, err := url.PathUnescape(token[4:])
		if err != nil {
			return ""
		}
		size := sizes[name]
		if n, rest, ok := strings.Cut(name, ":"); ok {
			v, err := strconv.ParseInt(n, 10, 32)
			if err != nil || rest == "" {
				return ""
			}
			size, name = int32(v), rest
		}
		if name == "" || size <= 0 || size > 1<<20 {
			return ""
		}
		key := fmt.Sprintf("Value_%d", size)
		types.layouts[key] = il2cppLayout{size: size, align: 1}
		return key
	}
	aliases := map[string]string{
		"int8": "int8_t", "uint8": "uint8_t", "int16": "int16_t", "uint16": "uint16_t",
		"int32": "int32_t", "uint32": "uint32_t", "int64": "int64_t", "uint64": "uint64_t",
		"float32": "float", "float64": "double", "char16": "uint16_t",
	}
	if alias, ok := aliases[token]; ok {
		return alias
	}
	if il2cppPrimitive(token) != nil {
		return token
	}
	return ""
}

func loadIL2CPPValueSizes(script string) (map[string]int32, error) {
	path := filepath.Join(filepath.Dir(script), "sizes.tsv")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil // inline val:SIZE:NAME does not need a sidecar
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 32<<20 {
		return nil, fmt.Errorf("sizes.tsv must be a regular file of at most 32 MiB")
	}
	sizes := map[string]int32{}
	scan := bufio.NewScanner(io.LimitReader(f, (32<<20)+1))
	scan.Buffer(make([]byte, 4096), 65536)
	for scan.Scan() {
		cols := strings.Split(strings.TrimSuffix(scan.Text(), "\r"), "\t")
		if len(cols) != 4 || cols[1] != "struct" {
			continue
		}
		instance, err := strconv.ParseInt(cols[2], 10, 32)
		if err != nil || instance <= 16 || instance-16 > 1<<20 {
			continue
		}
		size := int32(instance - 16) // this exporter includes the x64 object header
		if old, exists := sizes[cols[0]]; exists && old != size {
			sizes[cols[0]] = 0
		} else if !exists {
			sizes[cols[0]] = size
		}
	}
	return sizes, scan.Err()
}
