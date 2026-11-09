package analyze

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"golang.org/x/arch/x86/x86asm"
)

// Recover the runtime layout from the exported accessor, never from a game
// address or a metadata-version guess. Unknown instruction patterns stay opaque.
type il2cppAffine struct {
	object, method, klass, slot, constant int64
	valid                                 bool
}

func il2cppRegister(r x86asm.Reg) x86asm.Reg {
	if r >= x86asm.AL && r <= x86asm.BL {
		return r - x86asm.AL + x86asm.RAX
	}
	if r >= x86asm.AH && r <= x86asm.BH {
		return r - x86asm.AH + x86asm.RAX
	}
	if r >= x86asm.SPB && r <= x86asm.R15B {
		return r - x86asm.SPB + x86asm.RSP
	}
	if r >= x86asm.AX && r <= x86asm.R15W {
		return r - x86asm.AX + x86asm.RAX
	}
	if r >= x86asm.EAX && r <= x86asm.R15L {
		return r - x86asm.EAX + x86asm.RAX
	}
	return r
}

func (im *il2cppNativeImage) vtableOffset() int32 {
	pc := im.exports["il2cpp_object_get_virtual_method"]
	if pc == 0 {
		return 0
	}
	regs := map[x86asm.Reg]il2cppAffine{x86asm.RCX: {object: 1, valid: true}, x86asm.RDX: {method: 1, valid: true}}
	read := func(a x86asm.Arg) il2cppAffine {
		switch a := a.(type) {
		case x86asm.Reg:
			v := regs[il2cppRegister(a)]
			if a < x86asm.EAX || a < x86asm.RAX && (v.object != 0 || v.method != 0 || v.klass != 0) {
				return il2cppAffine{}
			}
			return v
		case x86asm.Imm:
			return il2cppAffine{constant: int64(a), valid: true}
		}
		return il2cppAffine{}
	}
	jumps := 0
	for n := 0; n < 128; n++ {
		var code []byte
		for _, s := range im.sections {
			if s.exec && pc >= s.va && pc-s.va < uint64(len(s.data)) {
				code = s.data[pc-s.va:]
				break
			}
		}
		if len(code) == 0 {
			return 0
		}
		ins, err := x86asm.Decode(code, 64)
		if err != nil {
			return 0
		}
		next := pc + uint64(ins.Len)
		if ins.Op == x86asm.JMP {
			if jumps >= 4 {
				return 0
			}
			rel, ok := ins.Args[0].(x86asm.Rel)
			if !ok {
				return 0
			}
			pc = uint64(int64(next) + int64(rel))
			jumps++
			continue
		}
		if ins.Op == x86asm.CALL || ins.Op == x86asm.RET {
			return 0
		}
		// A conditional fall-through is one valid control-flow path. Stop at
		// calls; no register value is propagated across an unmodeled callee.
		if isCondJump(ins.Op) {
			pc = next
			continue
		}
		switch ins.Op {
		case x86asm.MOV, x86asm.MOVZX, x86asm.LEA, x86asm.ADD, x86asm.SUB, x86asm.CMP, x86asm.TEST, x86asm.PUSH, x86asm.POP, x86asm.NOP:
		default:
			return 0
		}
		dst, isReg := ins.Args[0].(x86asm.Reg)
		if isReg {
			originalDst := dst
			dst = il2cppRegister(dst)
			v := il2cppAffine{}
			switch ins.Op {
			case x86asm.MOV, x86asm.MOVZX, x86asm.LEA:
				v = read(ins.Args[1])
				if mem, ok := ins.Args[1].(x86asm.Mem); ok {
					base, index := regs[il2cppRegister(mem.Base)], regs[il2cppRegister(mem.Index)]
					if mem.Index == 0 {
						index = il2cppAffine{valid: true}
					}
					if base.valid && index.valid && mem.Segment == 0 {
						scale := int64(mem.Scale)
						v = il2cppAffine{object: base.object + index.object*scale, method: base.method + index.method*scale, klass: base.klass + index.klass*scale, slot: base.slot + index.slot*scale, constant: base.constant + index.constant*scale + mem.Disp, valid: true}
						if ins.Op != x86asm.LEA {
							switch {
							case v.object == 1 && v.method == 0 && v.klass == 0 && v.slot == 0 && v.constant == 0 && ins.MemBytes == 8:
								v = il2cppAffine{klass: 1, valid: true}
							case v.method == 1 && v.object == 0 && v.klass == 0 && v.slot == 0 && v.constant >= 0 && ins.MemBytes == 2:
								v = il2cppAffine{slot: 1, valid: true}
							case v.klass == 1 && v.slot == 16 && v.object == 0 && v.method == 0 && v.constant >= 24 && v.constant <= 65544 && ins.MemBytes == 8:
								// This accessor loads the MethodInfo (second member of VirtualInvokeData).
								off := v.constant - 8
								if off%8 == 0 {
									return int32(off)
								}
								return 0
							default:
								v = il2cppAffine{}
							}
						}
					} else {
						v = il2cppAffine{}
					}
				}
			case x86asm.ADD:
				a, b := regs[dst], read(ins.Args[1])
				if a.valid && b.valid {
					v = il2cppAffine{object: a.object + b.object, method: a.method + b.method, klass: a.klass + b.klass, slot: a.slot + b.slot, constant: a.constant + b.constant, valid: true}
				}
			case x86asm.CMP, x86asm.TEST, x86asm.PUSH:
				pc = next
				continue
			}
			if originalDst < x86asm.EAX || originalDst < x86asm.RAX && (v.object != 0 || v.method != 0 || v.klass != 0) {
				v = il2cppAffine{}
			}
			if v.constant > 1<<20 || v.constant < -(1<<20) || v.slot > 1<<20 || v.slot < 0 || v.object > 1 || v.method > 1 || v.klass > 1 {
				v = il2cppAffine{}
			}
			regs[dst] = v
		}
		pc = next
	}
	return 0
}

func (t *il2cppNativeTypes) classRecords() ([]il2cppClassRecord, error) {
	var rows []il2cppClassRecord
	specCount, _ := t.image.pointer(t.registration.address + 0x40)
	specPointer, _ := t.image.pointer(t.registration.address + 0x48)
	for i, r := range t.metadata.types {
		if r.bits&1 != 0 || r.flags&0x20 != 0 || r.generic >= 0 {
			continue
		}
		size, name := t.instanceSize(i), t.name(i, 0)
		if size == 0 || name == "" {
			continue
		}
		row := il2cppClassRecord{ID: strconv.Itoa(i), Name: name, Size: int32(size), Fields: t.classFields(i)}
		if len(row.Fields) > 4096 || r.vtableCount > 4096 {
			continue
		}
		for slot := 0; slot < r.vtableCount; slot++ {
			start := (r.vtableStart + slot) * 4
			if start < 0 || start+4 > len(t.metadata.tables[17].data) {
				return nil, fmt.Errorf("IL2CPP vtable exceeds metadata")
			}
			raw := binary.LittleEndian.Uint32(t.metadata.tables[17].data[start:])
			kind, index := raw>>29, int((raw&0x1ffffffe)>>1)
			switch kind {
			case 3:
			case 6:
				if uint64(index) >= specCount {
					return nil, fmt.Errorf("IL2CPP vtable method spec exceeds table")
				}
				d := t.image.read(specPointer+uint64(index)*12, 4)
				if d == nil {
					return nil, fmt.Errorf("unmapped IL2CPP vtable method spec")
				}
				index = int(binary.LittleEndian.Uint32(d))
			default:
				continue
			}
			if index < 0 || index >= len(t.metadata.methods) {
				return nil, fmt.Errorf("IL2CPP vtable method exceeds metadata")
			}
			row.Slots = append(row.Slots, il2cppVirtualSlot{Index: int32(slot), Method: strconv.Itoa(index)})
		}
		rows = append(rows, row)
	}
	return rows, nil
}
