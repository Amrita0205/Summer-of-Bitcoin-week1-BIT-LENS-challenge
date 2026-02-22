#!/usr/bin/env python3
"""
Bitcoin Transaction Analyzer
Parses raw Bitcoin transactions and outputs a structured JSON report.
"""

import sys
import json
import hashlib
import struct
import math
import os
from functools import lru_cache


# ---------------------------------------------------------------------------
# Bech32 / Bech32m (no external deps — implemented from BIP173/BIP350)
# ---------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

@lru_cache(maxsize=8192)
def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def _bech32_encode(hrp, data, spec):
    combined = data + [0, 0, 0, 0, 0, 0]
    const = 0x2bc830a3 if spec == "bech32m" else 1
    polymod = _bech32_polymod(tuple(_bech32_hrp_expand(hrp) + combined)) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join([CHARSET[d] for d in data + checksum])

def encode_segwit_address(hrp, witver, witprog):
    spec = "bech32m" if witver else "bech32"
    converted = _convertbits(witprog, 8, 5)
    if converted is None:
        return None
    return _bech32_encode(hrp, [witver] + converted, spec)


# ---------------------------------------------------------------------------
# Hashing & Base58
# ---------------------------------------------------------------------------

def _hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

@lru_cache(maxsize=4096)
def _base58check(payload: bytes) -> str:
    checksum = _sha256d(payload)[:4]
    data = payload + checksum
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(_B58[rem:rem+1])
    for byte in data:
        if byte == 0:
            result.append(b'1')
        else:
            break
    return b''.join(reversed(result)).decode('ascii')


# ---------------------------------------------------------------------------
# Address encoding
# ---------------------------------------------------------------------------

@lru_cache(maxsize=8192)
def _p2pkh_addr(pkh: bytes, mainnet=True) -> str:
    return _base58check((b'\x00' if mainnet else b'\x6f') + pkh)

@lru_cache(maxsize=8192)
def _p2sh_addr(sh: bytes, mainnet=True) -> str:
    return _base58check((b'\x05' if mainnet else b'\xc4') + sh)

@lru_cache(maxsize=8192)
def _p2wpkh_addr(pkh: bytes, mainnet=True) -> str:
    return encode_segwit_address('bc' if mainnet else 'tb', 0, list(pkh))

@lru_cache(maxsize=8192)
def _p2wsh_addr(sh: bytes, mainnet=True) -> str:
    return encode_segwit_address('bc' if mainnet else 'tb', 0, list(sh))

@lru_cache(maxsize=8192)
def _p2tr_addr(xpk: bytes, mainnet=True) -> str:
    return encode_segwit_address('bc' if mainnet else 'tb', 1, list(xpk))


# ---------------------------------------------------------------------------
# Script utilities
# ---------------------------------------------------------------------------

_OP_NAMES = {
    0x00: 'OP_0', 0x4c: 'OP_PUSHDATA1', 0x4d: 'OP_PUSHDATA2',
    0x4e: 'OP_PUSHDATA4', 0x4f: 'OP_1NEGATE', 0x51: 'OP_1',
    0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4', 0x55: 'OP_5',
    0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8', 0x59: 'OP_9',
    0x5a: 'OP_10', 0x5b: 'OP_11', 0x5c: 'OP_12', 0x5d: 'OP_13',
    0x5e: 'OP_14', 0x5f: 'OP_15', 0x60: 'OP_16',
    0x63: 'OP_IF', 0x64: 'OP_NOTIF', 0x67: 'OP_ELSE', 0x68: 'OP_ENDIF',
    0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN', 0x75: 'OP_DROP', 0x76: 'OP_DUP',
    0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY', 0x93: 'OP_ADD',
    0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256', 0xac: 'OP_CHECKSIG',
    0xad: 'OP_CHECKSIGVERIFY', 0xae: 'OP_CHECKMULTISIG',
    0xb1: 'OP_CHECKLOCKTIMEVERIFY', 0xb2: 'OP_CHECKSEQUENCEVERIFY',
}

@lru_cache(maxsize=16384)
def script_to_asm(script: bytes) -> str:
    if not script:
        return ''
    parts = []
    i = 0
    try:
        while i < len(script):
            op = script[i]; i += 1
            if 0x01 <= op <= 0x4b:
                data = script[i:i+op]; i += op
                parts.append(f'OP_PUSHBYTES_{op}')
                parts.append(data.hex())
            elif op == 0x4c:
                n = script[i]; i += 1
                parts.append('OP_PUSHDATA1')
                parts.append(script[i:i+n].hex()); i += n
            elif op == 0x4d:
                n = struct.unpack_from('<H', script, i)[0]; i += 2
                parts.append('OP_PUSHDATA2')
                parts.append(script[i:i+n].hex()); i += n
            elif op == 0x4e:
                n = struct.unpack_from('<I', script, i)[0]; i += 4
                parts.append('OP_PUSHDATA4')
                parts.append(script[i:i+n].hex()); i += n
            else:
                name = _OP_NAMES.get(op)
                if name is None:
                    name = f'OP_UNKNOWN_0x{op:02X}'
                parts.append(name)
    except Exception:
        pass
    return ' '.join(parts)


def classify_output_script(script: bytes, mainnet: bool):
    """Returns (script_type, address, extra_fields_dict)"""
    n = len(script)
    extras = {}

    # OP_RETURN
    if n >= 1 and script[0] == 0x6a:
        raw_data = script[1:]
        op_data = b''
        # Concatenate all push data after OP_RETURN
        pos = 0
        while pos < len(raw_data):
            b = raw_data[pos]
            if 0x01 <= b <= 0x4b:
                pos += 1
                op_data += raw_data[pos:pos+b]; pos += b
            elif b == 0x4c:
                pos += 1
                if pos < len(raw_data):
                    l = raw_data[pos]; pos += 1
                    op_data += raw_data[pos:pos+l]; pos += l
            elif b == 0x4d:
                pos += 1
                if pos + 2 <= len(raw_data):
                    l = struct.unpack_from('<H', raw_data, pos)[0]; pos += 2
                    op_data += raw_data[pos:pos+l]; pos += l
            elif b == 0x4e:
                pos += 1
                if pos + 4 <= len(raw_data):
                    l = struct.unpack_from('<I', raw_data, pos)[0]; pos += 4
                    op_data += raw_data[pos:pos+l]; pos += l
            elif b == 0x00:
                pos += 1  # OP_0, pushes empty bytes
            else:
                break  # non-push opcode or end
        extras['op_return_data_hex'] = op_data.hex()
        try:
            extras['op_return_data_utf8'] = op_data.decode('utf-8')
        except Exception:
            extras['op_return_data_utf8'] = None
        if op_data[:4] == b'omni' or op_data[:4] == b'\x6f\x6d\x6e\x69':
            extras['op_return_protocol'] = 'omni'
        elif len(op_data) >= 5 and op_data[:5] == bytes([0x01, 0x09, 0xf9, 0x11, 0x02]):
            extras['op_return_protocol'] = 'opentimestamps'
        else:
            extras['op_return_protocol'] = 'unknown'
        return 'op_return', None, extras

    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if (n == 25 and script[0] == 0x76 and script[1] == 0xa9 and
            script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac):
        return 'p2pkh', _p2pkh_addr(script[3:23], mainnet), extras

    # P2SH: OP_HASH160 <20> OP_EQUAL
    if n == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87:
        return 'p2sh', _p2sh_addr(script[2:22], mainnet), extras

    # P2WPKH: OP_0 <20>
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return 'p2wpkh', _p2wpkh_addr(script[2:22], mainnet), extras

    # P2WSH: OP_0 <32>
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return 'p2wsh', _p2wsh_addr(script[2:34], mainnet), extras

    # P2TR: OP_1 <32>
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return 'p2tr', _p2tr_addr(script[2:34], mainnet), extras

    return 'unknown', None, extras


def classify_input_script(script_sig: bytes, witness: list, prevout_script: bytes, mainnet: bool):
    """Returns (script_type, address_or_None)"""
    ps = prevout_script
    n = len(ps)

    # P2WPKH prevout
    if n == 22 and ps[0] == 0x00 and ps[1] == 0x14:
        return 'p2wpkh', _p2wpkh_addr(ps[2:22], mainnet)

    # P2WSH prevout
    if n == 34 and ps[0] == 0x00 and ps[1] == 0x20:
        return 'p2wsh', None

    # P2TR prevout
    if n == 34 and ps[0] == 0x51 and ps[1] == 0x20:
        # keypath: single 64-byte witness item (schnorr sig)
        if len(witness) == 1:
            return 'p2tr_keypath', _p2tr_addr(ps[2:34], mainnet)
        # with annex
        if len(witness) >= 2:
            last = bytes.fromhex(witness[-1]) if witness[-1] else b''
            if last[:1] == b'\x50' and len(witness) == 2:
                return 'p2tr_keypath', _p2tr_addr(ps[2:34], mainnet)
        return 'p2tr_scriptpath', None

    # P2PKH prevout
    if (n == 25 and ps[0] == 0x76 and ps[1] == 0xa9 and
            ps[2] == 0x14 and ps[23] == 0x88 and ps[24] == 0xac):
        return 'p2pkh', _p2pkh_addr(ps[3:23], mainnet)

    # P2SH prevout — check nested type from scriptSig
    if n == 23 and ps[0] == 0xa9 and ps[1] == 0x14 and ps[22] == 0x87:
        # P2SH-P2WPKH: scriptSig is exactly <push of 22-byte script> = 0x16 0x00 0x14 <20>
        if len(script_sig) == 23 and script_sig[0] == 0x16 and script_sig[1] == 0x00 and script_sig[2] == 0x14:
            return 'p2sh-p2wpkh', None
        # P2SH-P2WSH: scriptSig is <push of 34-byte script> = 0x22 0x00 0x20 <32>
        if len(script_sig) == 35 and script_sig[0] == 0x22 and script_sig[1] == 0x00 and script_sig[2] == 0x20:
            return 'p2sh-p2wsh', None
        # If witness is non-empty it's likely p2sh-p2wpkh or p2sh-p2wsh
        if witness:
            return 'p2sh-p2wpkh', None
        return 'p2sh-p2wsh', None

    return 'unknown', None


# ---------------------------------------------------------------------------
# Raw transaction parser
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos+n]
        if len(chunk) != n:
            raise ValueError(f"Unexpected end of data at pos {self.pos}: need {n}, have {len(chunk)}")
        self.pos += n
        return chunk

    def read_varint(self) -> int:
        first = self.read(1)[0]
        if first < 0xfd:
            return first
        elif first == 0xfd:
            return struct.unpack('<H', self.read(2))[0]
        elif first == 0xfe:
            return struct.unpack('<I', self.read(4))[0]
        else:
            return struct.unpack('<Q', self.read(8))[0]

    def read_varint_with_raw(self):
        """Returns (raw_bytes, value)"""
        first_byte = self.read(1)
        v = first_byte[0]
        if v < 0xfd:
            return first_byte, v
        elif v == 0xfd:
            extra = self.read(2)
            return first_byte + extra, struct.unpack('<H', extra)[0]
        elif v == 0xfe:
            extra = self.read(4)
            return first_byte + extra, struct.unpack('<I', extra)[0]
        else:
            extra = self.read(8)
            return first_byte + extra, struct.unpack('<Q', extra)[0]


def parse_raw_tx(raw_hex: str) -> dict:
    raw = bytes.fromhex(raw_hex)
    r = _Reader(raw)

    version = struct.unpack('<I', r.read(4))[0]

    # Detect segwit marker
    is_segwit = False
    if len(raw) > 5 and raw[4] == 0x00 and raw[5] == 0x01:
        is_segwit = True
        r.read(2)  # consume marker + flag

    vin_count = r.read_varint()
    inputs = []
    for _ in range(vin_count):
        txid = r.read(32)[::-1].hex()
        vout = struct.unpack('<I', r.read(4))[0]
        sl = r.read_varint()
        script_sig = r.read(sl)
        sequence = struct.unpack('<I', r.read(4))[0]
        inputs.append({'txid': txid, 'vout': vout, 'script_sig': script_sig, 'sequence': sequence, 'witness': []})

    vout_count = r.read_varint()
    outputs = []
    for i in range(vout_count):
        value = struct.unpack('<q', r.read(8))[0]
        sl = r.read_varint()
        script = r.read(sl)
        outputs.append({'n': i, 'value_sats': value, 'script_pubkey': script})

    if is_segwit:
        for inp in inputs:
            item_count = r.read_varint()
            items = []
            for _ in range(item_count):
                il = r.read_varint()
                items.append(r.read(il).hex())
            inp['witness'] = items

    locktime = struct.unpack('<I', r.read(4))[0]

    return {
        'raw': raw,
        'version': version,
        'is_segwit': is_segwit,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
    }


def _compute_txid(raw: bytes, is_segwit: bool) -> str:
    """Compute txid (stripped of witness for segwit)."""
    if not is_segwit:
        return _sha256d(raw)[::-1].hex()

    # Rebuild legacy serialization
    r = _Reader(raw)
    version = r.read(4)
    r.read(2)  # skip marker+flag

    vin_raw, vin_count = r.read_varint_with_raw()
    inputs_data = b''
    for _ in range(vin_count):
        txid = r.read(36)  # txid(32) + vout(4)
        sl_raw, sl = r.read_varint_with_raw()
        script = r.read(sl)
        seq = r.read(4)
        inputs_data += txid + sl_raw + script + seq

    vout_raw, vout_count = r.read_varint_with_raw()
    outputs_data = b''
    for _ in range(vout_count):
        val = r.read(8)
        sl_raw, sl = r.read_varint_with_raw()
        script = r.read(sl)
        outputs_data += val + sl_raw + script

    # skip witness
    for _ in range(vin_count):
        ic_raw, ic = r.read_varint_with_raw()
        for _ in range(ic):
            il_raw, il = r.read_varint_with_raw()
            r.read(il)

    locktime = r.read(4)
    legacy = version + vin_raw + inputs_data + vout_raw + outputs_data + locktime
    return _sha256d(legacy)[::-1].hex()


def _compute_weight_and_sizes(raw: bytes, is_segwit: bool):
    """Returns (size, witness_bytes, non_witness_bytes, weight)."""
    size = len(raw)
    if not is_segwit:
        return size, 0, size, size * 4

    # Parse to find witness boundaries
    r = _Reader(raw)
    r.read(4)   # version
    r.read(2)   # marker + flag
    _, vin_count = r.read_varint_with_raw()
    for _ in range(vin_count):
        r.read(32 + 4)
        _, sl = r.read_varint_with_raw()
        r.read(sl)
        r.read(4)
    _, vout_count = r.read_varint_with_raw()
    for _ in range(vout_count):
        r.read(8)
        _, sl = r.read_varint_with_raw()
        r.read(sl)

    witness_start = r.pos
    for _ in range(vin_count):
        _, ic = r.read_varint_with_raw()
        for _ in range(ic):
            _, il = r.read_varint_with_raw()
            r.read(il)
    witness_size = r.pos - witness_start

    # base_size = size without marker/flag and without witness
    base_size = size - 2 - witness_size
    # weight = base_size * 3 + total_size  (equivalent to base*4 + marker(2) + witness)
    weight = base_size * 3 + size
    non_witness = base_size
    return size, witness_size, non_witness, weight


# ---------------------------------------------------------------------------
# Locktime / sequence helpers
# ---------------------------------------------------------------------------

def decode_locktime(locktime: int):
    if locktime == 0:
        return 'none', 0
    elif locktime < 500000000:
        return 'block_height', locktime
    else:
        return 'unix_timestamp', locktime


def decode_sequence_timelock(sequence: int) -> dict:
    if sequence >= 0xFFFFFFFE:
        return {'enabled': False}
    if sequence & 0x80000000:
        return {'enabled': False}
    is_time = bool(sequence & (1 << 22))
    value = sequence & 0xFFFF
    return {
        'enabled': True,
        'type': '512s_intervals' if is_time else 'blocks',
        'value': value,
    }


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze(fixture_path: str) -> dict:
    with open(fixture_path) as f:
        fixture = json.load(f)

    network = fixture.get('network', 'mainnet')
    mainnet = (network == 'mainnet')
    raw_hex = fixture['raw_tx']
    prevouts_list = fixture.get('prevouts', [])

    # Build lookup by (txid_lower, vout)
    prevout_map = {(p['txid'].lower(), p['vout']): p for p in prevouts_list}

    tx = parse_raw_tx(raw_hex)
    raw = tx['raw']
    is_segwit = tx['is_segwit']

    txid = _compute_txid(raw, is_segwit)
    wtxid = _sha256d(raw)[::-1].hex() if is_segwit else None

    size, witness_bytes, non_witness_bytes, weight = _compute_weight_and_sizes(raw, is_segwit)
    vbytes = math.ceil(weight / 4)

    locktime_type, locktime_value = decode_locktime(tx['locktime'])

    # ---- Inputs ----
    total_input_sats = 0
    vin = []
    for inp in tx['inputs']:
        key = (inp['txid'].lower(), inp['vout'])
        po = prevout_map.get(key, {})
        value_sats = po.get('value_sats', 0)
        spk_hex = po.get('script_pubkey_hex', '')
        total_input_sats += value_sats

        prevout_script = bytes.fromhex(spk_hex) if spk_hex else b''
        script_sig = inp['script_sig']
        witness = inp['witness']

        stype, addr = classify_input_script(script_sig, witness, prevout_script, mainnet)
        rel_tl = decode_sequence_timelock(inp['sequence'])

        vin.append({
            'txid': inp['txid'],
            'vout': inp['vout'],
            'sequence': inp['sequence'],
            'script_sig_hex': script_sig.hex(),
            'script_asm': script_to_asm(script_sig),
            'witness': witness,
            'script_type': stype,
            'address': addr,
            'prevout': {
                'value_sats': value_sats,
                'script_pubkey_hex': spk_hex,
            },
            'relative_timelock': rel_tl,
        })

    # ---- Outputs ----
    total_output_sats = 0
    vout = []
    for out in tx['outputs']:
        script = out['script_pubkey']
        total_output_sats += out['value_sats']
        stype, addr, extras = classify_output_script(script, mainnet)
        entry = {
            'n': out['n'],
            'value_sats': out['value_sats'],
            'script_pubkey_hex': script.hex(),
            'script_asm': script_to_asm(script),
            'script_type': stype,
            'address': addr,
        }
        entry.update(extras)
        vout.append(entry)

    # ---- Fees & rate ----
    fee_sats = total_input_sats - total_output_sats
    fee_rate = round(fee_sats / vbytes, 2) if vbytes else 0.0

    # ---- RBF ----
    rbf = any(inp['sequence'] < 0xFFFFFFFE for inp in tx['inputs'])

    # ---- Warnings ----
    warnings = []
    if rbf:
        warnings.append({'code': 'RBF_SIGNALING',
                         'message': 'Transaction signals Replace-By-Fee (RBF).'})
    if fee_sats > 1_000_000 or fee_rate > 200:
        warnings.append({'code': 'HIGH_FEE',
                         'message': f'Unusually high fee: {fee_sats} sats at {fee_rate} sat/vB.'})
    if any(o['script_type'] != 'op_return' and o['value_sats'] < 546 for o in vout):
        warnings.append({'code': 'DUST_OUTPUT',
                         'message': 'One or more outputs are below the dust threshold (546 sats).'})
    if any(o['script_type'] == 'unknown' for o in vout):
        warnings.append({'code': 'UNKNOWN_OUTPUT_SCRIPT',
                         'message': 'One or more outputs have an unrecognized script type.'})

    # ---- Segwit savings ----
    segwit_savings = None
    if is_segwit:
        weight_if_legacy = (size - witness_bytes - 2) * 4
        savings_pct = round((1 - weight / weight_if_legacy) * 100, 2) if weight_if_legacy else 0.0
        segwit_savings = {
            'witness_bytes': witness_bytes,
            'non_witness_bytes': non_witness_bytes,
            'total_bytes': size,
            'weight_actual': weight,
            'weight_if_legacy': weight_if_legacy,
            'savings_pct': savings_pct,
        }

    return {
        'ok': True,
        'network': network,
        'segwit': is_segwit,
        'txid': txid,
        'wtxid': wtxid,
        'version': tx['version'],
        'locktime': tx['locktime'],
        'locktime_type': locktime_type,
        'locktime_value': locktime_value,
        'size_bytes': size,
        'weight': weight,
        'vbytes': vbytes,
        'total_input_sats': total_input_sats,
        'total_output_sats': total_output_sats,
        'fee_sats': fee_sats,
        'fee_rate_sat_vb': fee_rate,
        'rbf_signaling': rbf,
        'segwit_savings': segwit_savings,
        'vin': vin,
        'vout': vout,
        'warnings': warnings,
    }


def main():
    if len(sys.argv) < 2:
        err = {'ok': False, 'error': {'code': 'INVALID_ARGS', 'message': 'Usage: analyzer.py <fixture.json>'}}
        print(json.dumps(err))
        sys.exit(1)

    try:
        result = analyze(sys.argv[1])
    except Exception as e:
        err = {'ok': False, 'error': {'code': 'PARSE_ERROR', 'message': str(e)}}
        print(json.dumps(err))
        sys.exit(1)

    os.makedirs('out', exist_ok=True)
    out_path = f'out/{result["txid"]}.json'
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()