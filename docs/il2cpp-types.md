# IL2CPP class and virtual-slot types

Native v39 extraction on Windows x64 uses the same internal type contract when
`global-metadata.dat` is selected or auto-discovered. It resolves registrations,
method addresses (including generic aliases), instance fields and virtual slots
without an external runtime. The exported `il2cpp_object_get_virtual_method`
accessor must reveal the runtime's vtable offset before class types are applied;
an unrecognized accessor leaves direct prototypes available. No dump files are
written. Other metadata versions require the external exports described below.

For Windows x64, place an optional `il2cpp-types.json` beside the `methodsigs.tsv`
selected by `il2cpp_signatures`. Both files must declare the same binary SHA-256;
the signature loader also checks the image itself. `none` disables both sources.
No additional MCP tool or engine API is required. PDB/DWARF still takes precedence.

The export describes verified runtime layout. Metadata versions alone are not a
layout contract: obtain `vtable_offset` from the matching runtime headers or from
verified runtime code. Do not assume an offset based only on a Unity version.

```json
{
  "version": 1,
  "binary_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "pointer_size": 8,
  "vtable_offset": 32,
  "classes": [
    {
      "id": "type:1",
      "name": "Example",
      "size": 24,
      "fields": [{"name": "value", "offset": 16, "type": "int32"}],
      "slots": [{"index": 0, "method": "method:2"}]
    }
  ],
  "methods": [
    {"id": "method:1", "owner": "type:1", "addresses": ["0x140001000"],
     "static": false, "ret": "bool", "params": []},
    {"id": "method:2", "owner": "type:1", "addresses": [],
     "static": false, "ret": "bool", "params": ["int32"]}
  ]
}
```

The hash, address and layout above are illustrative. IDs must be unique within
the export and distinguish overloaded methods. They can be metadata definition
indices; names are never used to choose a virtual method. Addresses are exact
absolute VA strings, including all shared-generic aliases. A method without a
native address can still define a virtual slot's prototype.

Class `size` includes the 16-byte x64 object header. Instance fields use absolute
object offsets; provide inherited fields and inherited/overridden slots too.
The host adds `klass` at offset zero. Each virtual slot occupies 16 bytes:
`methodPtr` at `vtable_offset + index*16` and `MethodInfo*` eight bytes later.
Field and method type tokens follow the `methodsigs.tsv` contract; value fields
require an inline exact size (`val:SIZE:Type`). Reference names are percent-escaped.
Do not collapse instantiated generic layouts to their generic definition unless
the layout has been verified for that instantiation.

The host decorates only existing, ABI-compatible signatures. Receiver/reference
ambiguity at a shared address leaves its class decoration unapplied. Slot
prototypes include `this`, managed parameters and `MethodInfo*`; register storage
comes from the Windows x64 model. Every function-pointer code type receives a
unique nonempty name, as required by Gosleigh's existing type resolver.

Class graphs are built on demand per requested prototype, with at most 64
objects and three reference-field edges before falling back to untyped pointers.
Ambiguous reference names, unsupported fields, overlapping field layouts,
unknown slot signatures and hidden-return-buffer slots stay untyped. This does
not resolve interface dispatch helpers or prove a concrete runtime override;
it supplies the prototype where class types propagate to an indirect call.

Files are limited to 128 MiB, 100,000 classes and 1,000,000 methods, with per-record
field/slot/parameter limits. Missing files preserve signature-only behavior;
malformed, mismatched or unsupported present files report an error. File changes
invalidate the cached worker, and type identities include the export content hash.
