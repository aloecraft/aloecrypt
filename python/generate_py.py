import json
import re
from typing import Any

with open("api.json") as f:
    schema = json.load(f)

# ── Helpers ───────────────────────────────────────────────────────────────────

def snake_case(s: str) -> str:
    return re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', s).lower()

def rust_type_to_py(t: str, optional: bool = False) -> str:
    # Strip leading & from reference types (e.g. &PartyINTRO -> PartyINTRO)
    if t.startswith("&mut "):
        t = t[5:]
    elif t.startswith("&"):
        t = t[1:]
    if t == "Vec<u8>" or t == "[u8]":
        base = "bytes"
    elif t == "bool":
        base = "bool"
    elif t in ("u32", "u64", "usize"):
        base = "int"
    elif t == "String" or t == "str":
        base = "str"
    elif t.startswith("Result<"):
        inner = t[7:t.rfind(",")].strip()
        base = rust_type_to_py(inner)
    else:
        base = t
    if optional:
        return f"Optional[{base}]"
    return base

def make_plugin_name(namespace: str | None, struct_name: str, fn_name: str) -> str:
    """Build the WASM export function name matching build.rs convention."""
    if namespace:
        prefix = f"{namespace}___{struct_name.lower()}"
    else:
        prefix = struct_name.lower()
    return f"{prefix}_{fn_name}"

def make_fn_plugin_name(namespace: str, fn_name: str) -> str:
    """Build the WASM export function name for standalone functions."""
    ns_snake = namespace.replace(".", "_")
    return f"{ns_snake}___{fn_name}"

# ── Size computation ──────────────────────────────────────────────────────────

# Evaluate sz_consts (some are expressions referencing other consts)
sz_values: dict[str, int] = {}
for c in schema["sz_consts"]:
    name = c["name"]
    value = c["value"]
    try:
        sz_values[name] = int(value)
    except ValueError:
        # Expression like "SIGN_KEY_SZ + ENCRYPTED_TAG_SZ"
        sz_values[name] = eval(value, {"__builtins__": {}}, sz_values)

# Map byte alias names to their byte sizes
byte_alias_sizes: dict[str, int] = {}
for alias in schema["byte_aliases"]:
    name = alias["name"]
    length_expr = alias["length"]
    try:
        byte_alias_sizes[name] = int(length_expr)
    except ValueError:
        byte_alias_sizes[name] = eval(length_expr, {"__builtins__": {}}, sz_values)

def field_wire_size(field: dict) -> int:
    """Compute the wire byte size of a single field."""
    ftype = field["type"]
    is_optional = field.get("optional", "false") == "true"
    base_size = _type_wire_size(ftype)
    if is_optional:
        return 1 + base_size  # 1-byte flag + value
    return base_size

def _type_wire_size(ftype: str) -> int:
    """Compute wire size for a type name."""
    if ftype == "bool":
        return 1
    elif ftype == "u32":
        return 4
    elif ftype == "u64":
        return 8
    elif ftype in byte_alias_sizes:
        return byte_alias_sizes[ftype]
    elif ftype in struct_wire_sizes:
        return struct_wire_sizes[ftype]
    elif ftype == "Vec<u8>":
        raise ValueError(f"Vec<u8> is variable-length, cannot compute fixed size")
    else:
        raise ValueError(f"Unknown type for wire size: {ftype}")

def compute_struct_wire_size(model_name: str) -> int:
    """Compute total wire byte size for a struct."""
    fields = struct_to_fields[model_name]
    return sum(field_wire_size(f) for f in fields)

# ── Size computation ──────────────────────────────────────────────────────────

sz_values: dict[str, int] = {}
for c in schema["sz_consts"]:
    name = c["name"]
    value = c["value"]
    try:
        sz_values[name] = int(value)
    except ValueError:
        sz_values[name] = eval(value, {"__builtins__": {}}, sz_values)

byte_alias_sizes: dict[str, int] = {}
for alias in schema["byte_aliases"]:
    name = alias["name"]
    length_expr = alias["length"]
    try:
        byte_alias_sizes[name] = int(length_expr)
    except ValueError:
        byte_alias_sizes[name] = eval(length_expr, {"__builtins__": {}}, sz_values)

def _type_wire_size(ftype: str) -> int | None:
    if ftype == "bool":
        return 1
    elif ftype == "u32":
        return 4
    elif ftype == "u64":
        return 8
    elif ftype in byte_alias_sizes:
        return byte_alias_sizes[ftype]
    elif ftype in struct_wire_sizes:
        return struct_wire_sizes[ftype]
    elif ftype == "Vec<u8>":
        return None
    else:
        raise ValueError(f"Unknown type for wire size: {ftype}")

def field_wire_size(field: dict) -> int | None:
    ftype = field["type"]
    is_optional = field.get("optional", "false") == "true"
    base_size = _type_wire_size(ftype)
    if base_size is None:
        return None
    if is_optional:
        return 1 + base_size
    return base_size

# Build lookups
byte_alias_names = {a["name"] for a in schema["byte_aliases"]}
struct_to_namespace: dict[str, str] = {}
struct_to_fields: dict[str, list] = {}
for ns_block in schema["models"]:
    ns = ns_block["namespace"]
    for name, defn in ns_block["models"].items():
        struct_to_namespace[name] = ns
        struct_to_fields[name] = defn["fields"]

trait_lookup: dict[str, dict] = {}
for t in schema["traits"]:
    trait_lookup[t["name"]] = t

# Compute struct wire sizes (must be done in dependency order)
struct_wire_sizes: dict[str, int] = {}

def _resolve_struct_wire_size(name: str) -> int:
    if name in struct_wire_sizes:
        return struct_wire_sizes[name]
    fields = struct_to_fields[name]
    total = 0
    for f in fields:
        ftype = f["type"]
        is_opt = f.get("optional", "false") == "true"
        if ftype in struct_to_fields and ftype not in struct_wire_sizes:
            _resolve_struct_wire_size(ftype)
        base = _type_wire_size(ftype)
        if base is None:
            struct_wire_sizes[name] = None
            return None
        total += (1 + base) if is_opt else base
    struct_wire_sizes[name] = total
    return total
for name in struct_to_fields:
    _resolve_struct_wire_size(name)

def _resolve_struct_wire_size(name: str) -> int | None:
    if name in struct_wire_sizes:
        return struct_wire_sizes[name]
    fields = struct_to_fields[name]
    total = 0
    for f in fields:
        ftype = f["type"]
        is_opt = f.get("optional", "false") == "true"
        if ftype in struct_to_fields and ftype not in struct_wire_sizes:
            _resolve_struct_wire_size(ftype)
        base = _type_wire_size(ftype)
        if base is None:
            if ftype in struct_wire_sizes and struct_wire_sizes[ftype] is None:
                struct_wire_sizes[name] = None
                return None
            struct_wire_sizes[name] = None
            return None
        total += (1 + base) if is_opt else base
    struct_wire_sizes[name] = total
    return total

for name in struct_to_fields:
    _resolve_struct_wire_size(name)

def is_byte_alias(t: str) -> bool:
    return t.strip("&") in byte_alias_names

def is_self_fn(func: dict) -> bool:
    inst = func.get("instance", "")
    return inst in ("&self", "&mut self")

def is_mut_self(func: dict) -> bool:
    return func.get("instance", "") == "&mut self"

def needs_rng(func: dict) -> bool:
    return any(p["type"] == "&mut dyn CryptoRngCore" for p in func.get("params", []))

def real_params(func: dict) -> list[dict]:
    return [p for p in func.get("params", []) if p["type"] != "&mut dyn CryptoRngCore"]

def return_is_result(func: dict) -> bool:
    return func["return"].startswith("Result<")

def inner_return_type(func: dict) -> str:
    ret = func["return"]
    if ret.startswith("Result<"):
        return ret[7:ret.rfind(",")].strip()
    return ret

# ── Generate api.py ───────────────────────────────────────────────────────────

def generate_api():
    lines = []
    lines.append("# This file is auto-generated by generate_py.py. Do not edit manually.")
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("from typing import Optional, NewType")
    lines.append("from aloecrypt._plugin import _PluginModel")
    lines.append("")

    # Size constants
    lines.append("# --- Size Constants ---")
    lines.append("")
    lines.append("class consts_api:")
    for c in schema["sz_consts"]:
        name = c["name"]
        value = c["value"]
        lines.append(f"    {name}: int = {value}")
    lines.append("")

    lines.append("# Flat const references for use in type aliases")
    for c in schema["sz_consts"]:
        lines.append(f"{c['name']} = consts_api.{c['name']}")
    lines.append("")

    # Byte type aliases
    lines.append("# --- Byte Type Aliases ---")
    lines.append("")
    for alias in schema["byte_aliases"]:
        lines.append(f"{alias['name']} = NewType('{alias['name']}', bytes)")
    lines.append("")

    # Wire field serialization helpers (used during generation)
    def _emit_write_field(lines, fname, ftype, indent):
        """Emit code to write a single field to buf at off."""
        if ftype == "bool":
            lines.append(f"{indent}buf[off] = int(self.{fname}); off += 1")
        elif ftype == "u32":
            lines.append(f"{indent}buf[off:off+4] = self.{fname}.to_bytes(4, 'little'); off += 4")
        elif ftype == "u64":
            lines.append(f"{indent}buf[off:off+8] = self.{fname}.to_bytes(8, 'little'); off += 8")
        elif ftype in byte_alias_sizes:
            sz = byte_alias_sizes[ftype]
            lines.append(f"{indent}buf[off:off+{sz}] = self.{fname}; off += {sz}")
        elif ftype in struct_wire_sizes:
            sz = struct_wire_sizes[ftype]
            lines.append(f"{indent}buf[off:off+{sz}] = self.{fname}.to_wire_bytes(); off += {sz}")
        else:
            raise ValueError(f"Cannot emit write for type: {ftype}")

    def _emit_read_field(lines, fname, ftype, indent):
        """Emit code to read a single field from data at off."""
        if ftype == "bool":
            lines.append(f"{indent}{fname} = bool(data[off]); off += 1")
        elif ftype == "u32":
            lines.append(f"{indent}{fname} = int.from_bytes(data[off:off+4], 'little'); off += 4")
        elif ftype == "u64":
            lines.append(f"{indent}{fname} = int.from_bytes(data[off:off+8], 'little'); off += 8")
        elif ftype in byte_alias_sizes:
            sz = byte_alias_sizes[ftype]
            lines.append(f"{indent}{fname} = data[off:off+{sz}]; off += {sz}")
        elif ftype in struct_wire_sizes:
            sz = struct_wire_sizes[ftype]
            lines.append(f"{indent}{fname} = {ftype}.from_wire_bytes(data[off:off+{sz}]); off += {sz}")
        else:
            raise ValueError(f"Cannot emit read for type: {ftype}")

    def _emit_write_field(lines, fname, ftype, indent):
        if ftype == "bool":
            lines.append(f"{indent}buf.append(int(self.{fname}))")
        elif ftype == "u32":
            lines.append(f"{indent}buf.extend(self.{fname}.to_bytes(4, 'little'))")
        elif ftype == "u64":
            lines.append(f"{indent}buf.extend(self.{fname}.to_bytes(8, 'little'))")
        elif ftype in byte_alias_sizes:
            sz = byte_alias_sizes[ftype]
            lines.append(f"{indent}assert len(self.{fname}) == {sz}, f'{fname} must be {sz} bytes, got {{len(self.{fname})}}'")
            lines.append(f"{indent}buf.extend(self.{fname})")
        elif ftype in struct_wire_sizes:
            lines.append(f"{indent}buf.extend(self.{fname}.to_wire_bytes())")
        elif ftype == "Vec<u8>":
            lines.append(f"{indent}buf.extend(len(self.{fname}).to_bytes(4, 'little'))")
            lines.append(f"{indent}buf.extend(self.{fname})")
        else:
            raise ValueError(f"Cannot emit write for type: {ftype}")

    def _emit_read_field(lines, fname, ftype, indent):
        if ftype == "bool":
            lines.append(f"{indent}{fname} = bool(data[off]); off += 1")
        elif ftype == "u32":
            lines.append(f"{indent}{fname} = int.from_bytes(data[off:off+4], 'little'); off += 4")
        elif ftype == "u64":
            lines.append(f"{indent}{fname} = int.from_bytes(data[off:off+8], 'little'); off += 8")
        elif ftype in byte_alias_sizes:
            sz = byte_alias_sizes[ftype]
            lines.append(f"{indent}{fname} = bytes(data[off:off+{sz}]); off += {sz}")
        elif ftype in struct_wire_sizes:
            ws = struct_wire_sizes[ftype]
            if ws is not None:
                lines.append(f"{indent}{fname} = {ftype}.from_wire_bytes(data[off:off+{ws}]); off += {ws}")
            else:
                lines.append(f"{indent}{fname} = {ftype}.from_wire_bytes_at(data, off); off += {fname}.wire_len()")
        elif ftype == "Vec<u8>":
            lines.append(f"{indent}_vlen = int.from_bytes(data[off:off+4], 'little'); off += 4")
            lines.append(f"{indent}{fname} = bytes(data[off:off+_vlen]); off += _vlen")
        else:
            raise ValueError(f"Cannot emit read for type: {ftype}")

    # Struct models
    lines.append("# --- Models ---")
    lines.append("")

    for ns_block in schema["models"]:
        ns = ns_block["namespace"]
        models = ns_block["models"]

        lines.append(f"class {ns}:")
        for model_name, model_def in models.items():
            lines.append(f"    class {model_name}(_PluginModel):")
            for field in model_def["fields"]:
                fname = field["name"]
                ftype = field["type"]
                is_optional = field.get("optional", "false") == "true"
                py_type = rust_type_to_py(ftype, is_optional)
                if is_optional:
                    lines.append(f"        {fname}: {py_type} = None")
                else:
                    lines.append(f"        {fname}: {py_type}")
            # Wire serialization methods
            fields = model_def["fields"]
            wire_sz = struct_wire_sizes[model_name]
            lines.append("")
            lines.append(f"        @classmethod")
            lines.append(f"        def wire_byte_sz(cls) -> int:")
            lines.append(f"            return {wire_sz}")
            lines.append("")

            # to_wire_bytes
            lines.append(f"        def to_wire_bytes(self) -> bytes:")
            lines.append(f"            buf = bytearray({wire_sz})")
            lines.append(f"            off = 0")
            for field in fields:
                fname = field["name"]
                ftype = field["type"]
                is_opt = field.get("optional", "false") == "true"
                if is_opt:
                    base_sz = _type_wire_size(ftype)
                    lines.append(f"            if self.{fname} is not None:")
                    lines.append(f"                buf[off] = 1; off += 1")
                    _emit_write_field(lines, fname, ftype, "                ")
                    lines.append(f"            else:")
                    lines.append(f"                buf[off] = 0; off += 1 + {base_sz}")
                else:
                    _emit_write_field(lines, fname, ftype, "            ")
            lines.append(f"            return bytes(buf)")
            lines.append("")

            # from_wire_bytes
            lines.append(f"        @classmethod")
            lines.append(f"        def from_wire_bytes(cls, data: bytes) -> '{model_name}':")
            lines.append(f"            off = 0")
            for field in fields:
                fname = field["name"]
                ftype = field["type"]
                is_opt = field.get("optional", "false") == "true"
                if is_opt:
                    base_sz = _type_wire_size(ftype)
                    lines.append(f"            if data[off] == 1:")
                    lines.append(f"                off += 1")
                    _emit_read_field(lines, fname, ftype, "                ")
                    lines.append(f"            else:")
                    lines.append(f"                off += 1 + {base_sz}")
                    lines.append(f"                {fname} = None")
                else:
                    _emit_read_field(lines, fname, ftype, "            ")
            # Constructor call
            ctor_args = ", ".join(f"{f['name']}={f['name']}" for f in fields)
            lines.append(f"            return cls({ctor_args})")
            # Wire serialization methods
            fields = model_def["fields"]
            wire_sz = struct_wire_sizes[model_name]
            lines.append("")
            lines.append(f"        @classmethod")
            lines.append(f"        def wire_byte_sz(cls) -> int:")
            if wire_sz is not None:
                lines.append(f"            return {wire_sz}")
            else:
                lines.append(f"            raise NotImplementedError('{model_name} has variable-length fields')")
            lines.append("")
            # to_wire_bytes
            lines.append(f"        def to_wire_bytes(self) -> bytes:")
            lines.append(f"            buf = bytearray()")
            for field in fields:
                fname = field["name"]
                ftype = field["type"]
                is_opt = field.get("optional", "false") == "true"
                if is_opt:
                    base_sz = _type_wire_size(ftype)
                    lines.append(f"            if self.{fname} is not None:")
                    lines.append(f"                buf.append(1)")
                    _emit_write_field(lines, fname, ftype, "                ")
                    lines.append(f"            else:")
                    if base_sz is not None:
                        lines.append(f"                buf.append(0)")
                        lines.append(f"                buf.extend(b'\\x00' * {base_sz})")
                    else:
                        lines.append(f"                buf.append(0)")
                        lines.append(f"                buf.extend(b'\\x00' * 4)")  # just length prefix of 0
                else:
                    _emit_write_field(lines, fname, ftype, "            ")
            lines.append(f"            return bytes(buf)")
            lines.append("")
            # from_wire_bytes
            lines.append(f"        @classmethod")
            lines.append(f"        def from_wire_bytes(cls, data: bytes) -> '{model_name}':")
            lines.append(f"            off = 0")
            for field in fields:
                fname = field["name"]
                ftype = field["type"]
                is_opt = field.get("optional", "false") == "true"
                if is_opt:
                    base_sz = _type_wire_size(ftype)
                    lines.append(f"            if data[off] == 1:")
                    lines.append(f"                off += 1")
                    _emit_read_field(lines, fname, ftype, "                ")
                    lines.append(f"            else:")
                    if base_sz is not None:
                        lines.append(f"                off += 1 + {base_sz}")
                    else:
                        lines.append(f"                off += 1 + 4")
                    lines.append(f"                {fname} = None")
                else:
                    _emit_read_field(lines, fname, ftype, "            ")
            ctor_args = ", ".join(f"{f['name']}={f['name']}" for f in fields)
            lines.append(f"            return cls({ctor_args})")
            lines.append("")

        lines.append("")

        for model_name in models:
            lines.append(f"{model_name} = {ns}.{model_name}")
        lines.append("")

    return "\n".join(lines)

# ── Generate traits.py ────────────────────────────────────────────────────────

def generate_traits():
    lines = []
    lines.append("# This file is auto-generated by generate_py.py. Do not edit manually.")
    lines.append("from aloecrypt._plugin import _wire_pack, _VarBytes, _VarStr, _Plugin")
    lines.append("from aloecrypt.api import *")
    lines.append("")
    lines.append("plugin = _Plugin()")
    lines.append("")

    lines.append("def _rebuild(obj, data_bytes, cls):")
    lines.append("    new = cls.from_wire_bytes(data_bytes)")
    lines.append("    obj.__dict__.update(new.__dict__)")
    lines.append("    return obj")
    lines.append("")

    for impl_entry in schema["impls"]:
        trait_name = impl_entry["trait"]
        struct_name = impl_entry["struct"]
        generics = [g for g in impl_entry.get("generics", []) if g]

        # Skip Into/From — handled in functions.py
        if trait_name in ("Into", "From"):
            continue

        trait_def = trait_lookup.get(trait_name)
        if not trait_def:
            lines.append(f"# WARNING: no trait definition for {trait_name}")
            continue

        ns = struct_to_namespace.get(struct_name)
        # For byte aliases, ns is None
        if struct_name in byte_alias_names:
            # Byte aliases don't have Python model classes to attach methods to
            # Skip for now — these are raw bytes types
            continue

        py_class = struct_name
        lines.append(f"# ── {py_class} :: {trait_name} ──")
        lines.append("")

        # Resolve generic type names for this impl
        trait_generics = [g for g in trait_def.get("generics", []) if g]
        generic_map = {}
        for i, tg in enumerate(trait_generics):
            if i < len(generics):
                generic_map[tg] = generics[i]

        for func in trait_def["functions"]:
            fn_name = func["name"]
            has_self = is_self_fn(func)
            is_mut = is_mut_self(func)
            has_rng_param = needs_rng(func)
            rparams = real_params(func)
            ret = func["return"]
            inner_ret = inner_return_type(func)

            # Skip trait methods that shadow struct fields (causes recursion in to_wire_bytes)
            struct_fields = {f["name"] for f in struct_to_fields.get(struct_name, [])}
            if fn_name in struct_fields:
                continue

            plugin_fn = make_plugin_name(ns, struct_name, fn_name)

            # Resolve generic types in params and return
            def resolve_type(t: str) -> str:
                for gname, gval in generic_map.items():
                    t = t.replace(gname, gval)
                return t

            resolved_ret = resolve_type(inner_ret)
            resolved_params = [(p["name"], resolve_type(p["type"])) for p in rparams]

            # Build Python parameter list (excluding self)
            py_params = []
            for pname, ptype in resolved_params:
                py_params.append(pname)

            pack_args = []
            if has_self:
                pack_args.append("self")
            for pname, ptype in resolved_params:
                clean_type = ptype.lstrip("&")
                if clean_type in ("Vec<u8>", "[u8]"):
                    pack_args.append(f"_VarBytes({pname})")
                elif clean_type in ("str", "String"):
                    pack_args.append(f"_VarStr({pname})")
                else:
                    pack_args.append(pname)
            if has_rng_param:
                pack_args.append("-1")

            pack_str = ", ".join(pack_args)
            call_expr = f"plugin.call(\"{plugin_fn}\", _wire_pack({pack_str}))"

            if inner_ret == "()" or ret == "()":
                if is_mut:
                    wrap_expr = f"_rebuild(self, {call_expr}, {py_class})"
                else:
                    wrap_expr = call_expr
            elif inner_ret == "bool":
                wrap_expr = f"bool({call_expr}[0])"
            elif inner_ret in ("u32", "u64", "usize"):
                wrap_expr = f"int.from_bytes({call_expr}, 'little')"
            elif inner_ret == "String":
                wrap_expr = f"{call_expr}.decode()"
            elif inner_ret == "Vec<u8>" or inner_ret in byte_alias_names:
                wrap_expr = call_expr
            elif inner_ret == "Self":
                if is_mut:
                    wrap_expr = f"_rebuild(self, {call_expr}, {py_class})"
                else:
                    wrap_expr = f"{py_class}.from_wire_bytes({call_expr})"
            elif resolved_ret in struct_to_fields:
                wrap_expr = f"{resolved_ret}.from_wire_bytes({call_expr})"
            else:
                wrap_expr = call_expr

            if has_self:
                if not py_params:
                    if inner_ret in ("bool", "u32", "u64", "usize") or inner_ret == "String" or inner_ret in byte_alias_names or inner_ret == "Vec<u8>":
                        lines.append(f"{py_class}.{fn_name} = property(lambda self: {wrap_expr})")
                    else:
                        lines.append(f"{py_class}.{fn_name} = lambda self: {wrap_expr}")
                else:
                    param_str = ", ".join(py_params)
                    lines.append(f"{py_class}.{fn_name} = lambda self, {param_str}: {wrap_expr}")
            else:
                if not py_params:
                    if inner_ret == "Self":
                        if has_rng_param:
                            lines.append(f"{py_class}.{fn_name} = classmethod(lambda cls: {py_class}.from_wire_bytes(plugin.call(\"{plugin_fn}\", _wire_pack(-1))))")
                        else:
                            lines.append(f"{py_class}.{fn_name} = classmethod(lambda cls: {py_class}.from_wire_bytes(plugin.call(\"{plugin_fn}\", b\"\")))")
                    else:
                        lines.append(f"{py_class}.{fn_name} = staticmethod(lambda: {wrap_expr})")
                else:
                    param_str = ", ".join(py_params)
                    if inner_ret == "Self":
                        cm_parts = []
                        for pname, ptype in resolved_params:
                            clean_type = ptype.lstrip("&")
                            if clean_type in ("Vec<u8>", "[u8]"):
                                cm_parts.append(f"_VarBytes({pname})")
                            elif clean_type in ("str", "String"):
                                cm_parts.append(f"_VarStr({pname})")
                            else:
                                cm_parts.append(pname)
                        if has_rng_param:
                            cm_parts.append("-1")
                        cm_pack = ", ".join(cm_parts)
                        lines.append(f"{py_class}.{fn_name} = classmethod(lambda cls, {param_str}: {py_class}.from_wire_bytes(plugin.call(\"{plugin_fn}\", _wire_pack({cm_pack}))))")
                    else:
                        lines.append(f"{py_class}.{fn_name} = staticmethod(lambda {param_str}: {wrap_expr})")
        lines.append("")

    return "\n".join(lines)

# ── Generate functions.py ─────────────────────────────────────────────────────

def generate_functions():
    lines = []
    lines.append("# This file is auto-generated by generate_py.py. Do not edit manually.")
    lines.append("from aloecrypt._plugin import _wire_pack, _VarBytes, _VarStr, _Plugin")
    lines.append("from aloecrypt.api import *")
    lines.append("")
    lines.append("plugin = _Plugin()")
    lines.append("")

    # Into/From conversions
    lines.append("# ── Into/From conversions ──")
    lines.append("")
    for impl_entry in schema["impls"]:
        trait_name = impl_entry["trait"]
        if trait_name not in ("Into", "From"):
            continue

        struct_name = impl_entry["struct"]
        generics = [g for g in impl_entry.get("generics", []) if g]

        ns_src = struct_to_namespace.get(struct_name)

        if trait_name == "Into" and generics:
            target = generics[0]
            plugin_fn = make_plugin_name(ns_src, struct_name, f"into_{target.lower()}")
            lines.append(f"{struct_name}.to_{snake_case(target)} = lambda self: {target}.from_wire_bytes(plugin.call(\"{plugin_fn}\", _wire_pack(self)))")

        elif trait_name == "From" and generics:
            source = generics[0]
            ns_target = struct_to_namespace.get(struct_name)
            plugin_fn = make_plugin_name(ns_target, struct_name, f"from_{source.lower()}")
            lines.append(f"{struct_name}.from_{snake_case(source)} = classmethod(lambda cls, val: {struct_name}.from_wire_bytes(plugin.call(\"{plugin_fn}\", _wire_pack(val))))")

    lines.append("")

    # Standalone functions
    lines.append("# ── Standalone functions ──")
    lines.append("")

    for ns_entry in schema.get("functions", []):
        namespace = ns_entry["namespace"]
        functions = ns_entry["functions"]

        lines.append(f"# ── {namespace} ──")
        lines.append("")

        for func in functions:
            fn_name = func["name"]
            rparams_list = real_params(func)
            has_rng_param = needs_rng(func)
            ret = func["return"]
            inner_ret = inner_return_type(func)

            plugin_fn = make_fn_plugin_name(namespace, fn_name)

            py_params = [p["name"] for p in rparams_list]
            param_str = ", ".join(py_params)
            pack_parts = []
            for p in rparams_list:
                pname = p["name"]
                ptype = p["type"].lstrip("&")
                if ptype in ("Vec<u8>", "[u8]"):
                    pack_parts.append(f"_VarBytes({pname})")
                elif ptype in ("str", "String"):
                    pack_parts.append(f"_VarStr({pname})")
                else:
                    pack_parts.append(pname)
            if has_rng_param:
                pack_parts.append("-1")
            pack_str = ", ".join(pack_parts)

            py_ret = rust_type_to_py(inner_ret)

            call = f"plugin.call(\"{plugin_fn}\", _wire_pack({pack_str}))"
            if inner_ret == "Vec<u8>" or inner_ret in byte_alias_names:
                wrap = call
            elif inner_ret == "String":
                wrap = f"{call}.decode()"
            elif inner_ret in ("u32", "u64", "usize"):
                wrap = f"int.from_bytes({call}, 'little')"
            elif inner_ret == "bool":
                wrap = f"bool({call}[0])"
            elif inner_ret in struct_to_fields:
                wrap = f"{inner_ret}.from_wire_bytes({call})"
            else:
                wrap = call

            lines.append(f"def {fn_name}({param_str}):")
            lines.append(f"    return {wrap}")
            lines.append("")

    # Convenience: perform_handshake
    lines.append("# ── Convenience functions ──")
    lines.append("")
    lines.append("def perform_handshake(session_a, session_b):")
    lines.append("    \"\"\"Run a full HELLO -> SYN -> ACK -> SYNACK -> WELCOME handshake.\"\"\"")
    lines.append("    intro_a = session_a.make_party_intro()")
    lines.append("    session_b.on_counterparty_intro(intro_a)")
    lines.append("    intro_b = session_b.make_party_intro()")
    lines.append("    cipher_b = session_b.make_party_cipher()")
    lines.append("    session_a.on_counterparty_intro(intro_b)")
    lines.append("    session_a.on_counterparty_cipher(cipher_b)")
    lines.append("    cipher_a = session_a.make_party_cipher()")
    lines.append("    challenge_a = session_a.make_party_challenge()")
    lines.append("    session_b.on_counterparty_cipher(cipher_a)")
    lines.append("    session_b.on_counterparty_challenge(challenge_a)")
    lines.append("    challenge_b = session_b.make_party_challenge()")
    lines.append("    response_b = session_b.make_party_challenge_response()")
    lines.append("    session_a.on_counterparty_challenge(challenge_b)")
    lines.append("    session_a.on_counterparty_challenge_response(response_b)")
    lines.append("    response_a = session_a.make_party_challenge_response()")
    lines.append("    session_b.on_counterparty_challenge_response(response_a)")
    lines.append("    return session_a.build(), session_b.build()")
    lines.append("")

    return "\n".join(lines)

# ── Generate api.pyi ──────────────────────────────────────────────────────────

def generate_api_pyi():
    lines = []
    lines.append("# This file is auto-generated by generate_py.py. Do not edit manually.")
    lines.append("from __future__ import annotations")
    lines.append("from typing import Optional")
    lines.append("")

    # Byte alias type stubs
    for alias in schema["byte_aliases"]:
        lines.append(f"{alias['name']} = bytes")
    lines.append("")

    # Build trait method lookup: struct_name -> [(fn_name, func_def, trait_name, generics)]
    struct_methods: dict[str, list] = {}
    for impl_entry in schema["impls"]:
        trait_name = impl_entry["trait"]
        struct_name = impl_entry["struct"]
        impl_generics = [g for g in impl_entry.get("generics", []) if g]

        if trait_name in ("Into", "From"):
            continue
        if struct_name in byte_alias_names:
            continue

        trait_def = trait_lookup.get(trait_name)
        if not trait_def:
            continue

        trait_generics = [g for g in trait_def.get("generics", []) if g]
        generic_map = {}
        for i, tg in enumerate(trait_generics):
            if i < len(impl_generics):
                generic_map[tg] = impl_generics[i]

        if struct_name not in struct_methods:
            struct_methods[struct_name] = []

        for func in trait_def["functions"]:
            struct_methods[struct_name].append((func, trait_name, generic_map))

    # Model stubs with method signatures
    for ns_block in schema["models"]:
        ns = ns_block["namespace"]
        lines.append(f"class {ns}:")
        for model_name, model_def in ns_block["models"].items():
            lines.append(f"    class {model_name}:")

            # Fields
            for field in model_def["fields"]:
                fname = field["name"]
                ftype = field["type"]
                is_optional = field.get("optional", "false") == "true"
                py_type = rust_type_to_py(ftype, is_optional)
                lines.append(f"        {fname}: {py_type}")

            # Methods from traits
            methods = struct_methods.get(model_name, [])
            if methods:
                lines.append("")
            for func, tname, gmap in methods:
                fn_name = func["name"]
                has_self = is_self_fn(func)
                rp = real_params(func)
                inner_ret = inner_return_type(func)

                def resolve(t: str) -> str:
                    for gn, gv in gmap.items():
                        t = t.replace(gn, gv)
                    return t

                resolved_ret = resolve(inner_ret)
                py_ret = rust_type_to_py(resolved_ret)
                if resolved_ret == "Self":
                    py_ret = model_name

                param_parts = []
                if has_self:
                    param_parts.append("self")
                else:
                    param_parts.append("cls")
                for p in rp:
                    pname = p["name"]
                    ptype = resolve(p["type"])
                    py_ptype = rust_type_to_py(ptype)
                    param_parts.append(f"{pname}: {py_ptype}")

                param_str = ", ".join(param_parts)

                if has_self:
                    lines.append(f"        def {fn_name}({param_str}) -> {py_ret}: ...")
                else:
                    lines.append(f"        @classmethod")
                    lines.append(f"        def {fn_name}({param_str}) -> {py_ret}: ...")

            lines.append("")
        lines.append("")

    # Top-level type aliases
    for ns_block in schema["models"]:
        ns = ns_block["namespace"]
        for model_name in ns_block["models"]:
            lines.append(f"{model_name} = {ns}.{model_name}")
    lines.append("")

    return "\n".join(lines)

# ── Generate __init__.py ──────────────────────────────────────────────────────

def generate_init():
    lines = []
    lines.append("# This file is auto-generated by generate_py.py. Do not edit manually.")
    lines.append("from aloecrypt._plugin import _Plugin")
    lines.append("from aloecrypt.api import *")
    lines.append("")

    # Collect all model names for model_rebuild
    all_models = []
    for ns_block in schema["models"]:
        ns = ns_block["namespace"]
        for model_name in ns_block["models"]:
            all_models.append(f"{ns}.{model_name}")

    # Resolve forward references
    lines.append("# Resolve forward references")
    lines.append("for _cls in [")
    for m in all_models:
        lines.append(f"    {m},")
    lines.append("]:")
    lines.append("    _cls.model_rebuild()")
    lines.append("")

    # Attach trait methods and functions
    lines.append("import aloecrypt.traits   # noqa: F401")
    lines.append("import aloecrypt.functions  # noqa: F401")
    lines.append("")

    # Version helper
    lines.append("def aloecrypt_version() -> str:")
    lines.append("    return _Plugin().call('aloecrypt_version', b'').decode()")
    lines.append("")

    # Re-export convenience
    lines.append("from aloecrypt.functions import perform_handshake")
    lines.append("")

    return "\n".join(lines)

# ── Write all files ───────────────────────────────────────────────────────────

import os
os.makedirs(".generated", exist_ok=True)

with open(".generated/api.py", "w") as f:
    f.write(generate_api())
print("Generated api.py")

with open(".generated/traits.py", "w") as f:
    f.write(generate_traits())
print("Generated traits.py")

with open(".generated/functions.py", "w") as f:
    f.write(generate_functions())
print("Generated functions.py")

with open(".generated/api.pyi", "w") as f:
    f.write(generate_api_pyi())
print("Generated api.pyi")

with open(".generated/__init__.py", "w") as f:
    f.write(generate_init())
print("Generated __init__.py")
