---
name: agent-tool-reversing
description: Reverse-engineer native binaries (PE/ELF/Mach-O) with the agent-tool MCP server - decompile and disassemble functions, find what references a string, address or struct field, map C++ classes, and inspect or patch a running process. Use when asked to analyze, reverse, decompile, disassemble or patch an executable, DLL, shared object or game client, to explain a crash address, or to find where a value, string or function is used in a binary.
---

# Reverse engineering with agent-tool

Order of work and judgment calls for the `analyze` (static), `memtool` (live
memory) and `debug` (DAP debugger) tools. Parameters are not repeated here; read
them from the server so they match the installed version:

    agent_tool_help(topic="analyze")             index of every operation
    agent_tool_help(topic="analyze/decompile")   one operation in full
    agent_tool_help(topic="memtool")             agent_tool_help(topic="debug")

If `analyze` is not exposed as a direct tool, go through `toolbox`:
`toolbox(operation="describe", tool="analyze", compact=true, tool_operation="decompile")`,
then `toolbox(operation="call", tool="analyze", arguments={...})`.

## 1. Orient, once per binary

1. `pe_info` / `elf_info` / `macho_info`: architecture, image base, sections, imports.
2. `entropy`, `overlay_detect`: a code section above 7 bits/byte is packed or
   encrypted. Static analysis of it is meaningless; read the unpacked code from
   the running process with memtool instead.
3. Know what names you have. A PDB beside a PE, embedded DWARF and IL2CPP
   metadata are applied automatically. Output full of `FUN_...` means no debug
   info: navigate by strings, imports and RTTI (`vtable_scan`).

## 2. Find the code from something observable

Do not read from the entry point. Start from evidence:

| You have | Call |
|---|---|
| A message, path or format string | `xref target_text="..."` |
| An API the code must call | IAT slot VA from `pe_info`, then `xref target_va=` |
| A magic number, error code, packet id | `instruction_search immediate=`, add `call_target=` to see which calls receive it |
| A struct field | `xref field="Class::member"` (debug types) or `instruction_search displacement=` |
| A C++ class | `vtable_scan`, then `rtti_dump` and `struct_layout` on its vtable |
| A crash or trace address | `function_at` |

## 3. Read the code

- Search and xref hits already name their function (`; in sub_140008070+0x47`):
  use that start. `sub_<hex>` and `FUN_<hex>` are generated names, not symbols;
  pass the hex address (`va="0x140008070"`).
- A bare address (crash, trace, pointer) goes through `function_at` first. Build
  only on `confidence` exact or high; `heuristic-misaligned` is a wrong start.
- `decompile` is the default way to read. Pass related functions together (up to
  16 in one `va`, comma-separated) instead of one call each; symbols work where
  addresses do (`va="Player::TakeDamage"`).
- `disassemble` when exact instructions matter: patch sites, byte signatures
  (`show_bytes=true`), flags and calling-convention details, or when the C looks wrong.
- `call_graph` before decompiling neighbours blindly; `type_info` for a type the
  C names but did not print.
- Imports print by name (`CreateFileW(...)`), also delay-loaded ones. An import
  by ordinal is named from the DLL beside the binary or in the Windows system
  folder; `Ordinal_<n>` remains when that DLL is not on this machine (`pe_info`
  shows which DLL it is).
- When decompile struggles:
  - `halt_baddata()`, "flow out of bounds" or "Flow exceeded maximum allowable
    instructions" mean obfuscation. Establish the real branch directions
    (debugger trace or disassembly) and pass them as `assume_branches`.
  - C that stops right after a call that should return: `noreturn_verify=true`.
  - A timeout: retry that one function with a larger `timeout_sec`.
- To search across every function, build a corpus once with the CLI
  (`agent-tool decompile-all`, run in the background through procexec) and grep
  the JSONL, rather than decompiling function by function.

## 4. Confirm at runtime

Static results use the image's linked addresses; a running process is relocated.
Runtime address = loaded module base + (VA - image base). Take the loaded base
from debug `modules` (memtool `regions` shows mapped files on Linux).

- memtool: `read` / `disasm` at the relocated address to confirm code or data,
  `read_chain` to resolve several pointer chains in one call, `search` then
  `filter` to locate a value, `write` to patch.
- debug: breakpoints, registers and stepping when the path taken matters.
- Do not launch an unknown or possibly malicious sample to answer what static
  analysis can answer; ask the user before running one.

## 5. Keep what you learn

A finding you will need again belongs in an annotation, not only in the chat:
`annotation_set` with `va`, a `comment`, `annotation_status` (hypothesis until
confirmed) and `evidence`. Saved notes are printed inside later `disassemble`
and `decompile` output. Use one `annotations_path` per project, pass it on
every call, and save several notes at once with `annotation_batch`.

## Reporting

For each claim say whether it was read from code (operation and address),
inferred, or confirmed at runtime. Give addresses as VAs with the function name.
