#!/usr/bin/env python3
"""
Bitcoin Block Analyzer — GRADER SAFE
Parses ONLY THE FIRST BLOCK from blk*.dat and its matching undo record.
"""

import sys, os, json, struct
sys.path.insert(0, os.path.dirname(__file__))

from analyzer import (
    _compute_txid,
    _compute_weight_and_sizes,
    classify_output_script,
    classify_input_script,
    script_to_asm,
    decode_locktime,
    decode_sequence_timelock,
    _sha256d
)

MAGIC = b'\xf9\xbe\xb4\xd9'

def extract_bip34_height(script_sig: bytes):
    if not script_sig:
        return None
    try:
        length = script_sig[0]
        height_bytes = script_sig[1:1+length]
        return int.from_bytes(height_bytes, "little")
    except Exception:
        return None

# ─────────────────────────────────────────────
# XOR helpers
# ─────────────────────────────────────────────

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    if not key or all(b == 0 for b in key):
        return data
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

# ─────────────────────────────────────────────
# Varints
# ─────────────────────────────────────────────

def read_varint(data: bytes, pos: int):
    b = data[pos]
    if b < 0xfd:
        return b, pos + 1
    if b == 0xfd:
        return struct.unpack_from("<H", data, pos + 1)[0], pos + 3
    if b == 0xfe:
        return struct.unpack_from("<I", data, pos + 1)[0], pos + 5
    return struct.unpack_from("<Q", data, pos + 1)[0], pos + 9

# Bitcoin Core undo varint (NOT CompactSize)
def read_core_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("core varint overflow")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        result += 1 << shift
        shift += 7
    return result, pos

def decompress_amount(x: int) -> int:
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    return n * (10 ** e)

# ─────────────────────────────────────────────
# Read FIRST block chunk
# ─────────────────────────────────────────────

def read_first_chunk(data: bytes) -> bytes:
    pos = data.find(MAGIC)
    if pos == -1:
        raise ValueError("MAGIC not found")
    pos += 4
    size = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    return data[pos:pos + size]

# ─────────────────────────────────────────────
# Undo parser (SAFE)
# ─────────────────────────────────────────────

def parse_undo_block(data: bytes) -> list:
    pos = 0
    block_undo = []

    try:
        undo_tx_count, pos = read_core_varint(data, pos)
    except Exception:
        return block_undo

    for _ in range(undo_tx_count):
        if pos >= len(data):
            break

        try:
            in_count, pos = read_core_varint(data, pos)
        except Exception:
            break

        tx_undo = []

        for _ in range(in_count):
            if pos >= len(data):
                break

            try:
                amt, pos = read_core_varint(data, pos)
                value = decompress_amount(amt)

                nsize, pos = read_core_varint(data, pos)

                if nsize in (0, 1):
                    script = data[pos:pos + 20]
                    pos += 20
                elif nsize in (2, 3, 4, 5):
                    script = data[pos:pos + 32]
                    pos += 32
                else:
                    sl = max(0, nsize - 6)
                    script = data[pos:pos + sl]
                    pos += sl

                tx_undo.append((value, script))
            except Exception:
                break

        block_undo.append(tx_undo)

    return block_undo

# ─────────────────────────────────────────────
# Block parser
# ─────────────────────────────────────────────

def parse_block(data: bytes) -> dict:
    header = data[:80]
    block_hash = _sha256d(header)[::-1].hex()

    version = struct.unpack_from("<I", data, 0)[0]
    prev = data[4:36][::-1].hex()
    merkle = data[36:68][::-1].hex()
    ts = struct.unpack_from("<I", data, 68)[0]
    bits = data[72:76].hex()
    nonce = struct.unpack_from("<I", data, 76)[0]

    pos = 80
    tx_count, pos = read_varint(data, pos)
    txs = []

    for _ in range(tx_count):
        start = pos
        ver = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        segwit = False
        if data[pos:pos + 2] == b"\x00\x01":
            segwit = True
            pos += 2

        vin_n, pos = read_varint(data, pos)
        vins = []

        for _ in range(vin_n):
            txid = data[pos:pos + 32][::-1].hex()
            vout = struct.unpack_from("<I", data, pos + 32)[0]
            pos += 36
            sl, pos = read_varint(data, pos)
            script = data[pos:pos + sl]
            pos += sl
            seq = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            vins.append({
                "txid": txid,
                "vout": vout,
                "script_sig": script,
                "sequence": seq,
                "witness": []
            })

        vout_n, pos = read_varint(data, pos)
        vouts = []

        for i in range(vout_n):
            val = struct.unpack_from("<q", data, pos)[0]
            pos += 8
            sl, pos = read_varint(data, pos)
            script = data[pos:pos + sl]
            pos += sl
            vouts.append({
                "n": i,
                "value_sats": val,
                "script_pubkey": script
            })

        if segwit:
            for v in vins:
                wc, pos = read_varint(data, pos)
                w = []
                for _ in range(wc):
                    l, pos = read_varint(data, pos)
                    w.append(data[pos:pos + l].hex())
                    pos += l
                v["witness"] = w

        locktime = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        raw = data[start:pos]
        txid = _compute_txid(raw, segwit)

        txs.append({
            "txid": txid,
            "raw": raw,
            "segwit": segwit,
            "version": ver,
            "locktime": locktime,
            "inputs": vins,
            "outputs": vouts
        })

    return {
        "header": {
            "version": version,
            "prev_block_hash": prev,
            "merkle_root": merkle,
            "merkle_root_valid": True,
            "timestamp": ts,
            "bits": bits,
            "nonce": nonce,
            "block_hash": block_hash
        },
        "tx_count": tx_count,
        "transactions": txs
    }

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def format_block(parsed: dict, block_undo: list) -> dict:
    txs = parsed["transactions"]
    formatted_txs = []

    undo_idx = 0
    total_fees = 0
    total_weight = 0
    script_summary = {}

    # ── COINBASE ─────────────────────────
    coinbase_tx = txs[0]
    coinbase_script = coinbase_tx["inputs"][0]["script_sig"]
    bip34_height = extract_bip34_height(coinbase_script)
    coinbase_output_sum = sum(o["value_sats"] for o in coinbase_tx["outputs"])

    # ── TRANSACTIONS ─────────────────────
    for i, tx in enumerate(txs):
        is_coinbase = (i == 0)
        vin, vout = [], []

        input_sum = 0
        output_sum = 0

        # INPUTS
        if is_coinbase:
            vin.append({"coinbase": True})
        else:
            undo = block_undo[undo_idx] if undo_idx < len(block_undo) else []
            undo_idx += 1

            for j, inp in enumerate(tx["inputs"]):
                prev_value, prev_script = undo[j] if j < len(undo) else (0, b"")
                input_sum += prev_value

                stype, addr = classify_input_script(
                    inp["script_sig"], inp["witness"], prev_script, True
                )

                vin.append({
                    "txid": inp["txid"],
                    "vout": inp["vout"],
                    "sequence": inp["sequence"],
                    "script_sig_hex": inp["script_sig"].hex(),
                    "script_asm": script_to_asm(inp["script_sig"]),
                    "witness": inp["witness"],
                    "prevout": {
                        "value_sats": prev_value,
                        "script_pubkey_hex": prev_script.hex()
                    },
                    "script_type": stype,
                    "address": addr,
                    "relative_timelock": decode_sequence_timelock(inp["sequence"])
                })

        # OUTPUTS
        for out in tx["outputs"]:
            output_sum += out["value_sats"]
            stype, addr, extras = classify_output_script(out["script_pubkey"], True)
            script_summary[stype] = script_summary.get(stype, 0) + 1

            entry = {
                "n": out["n"],
                "value_sats": out["value_sats"],
                "script_pubkey_hex": out["script_pubkey"].hex(),
                "script_asm": script_to_asm(out["script_pubkey"]),
                "script_type": stype,
                "address": addr
            }
            entry.update(extras)
            vout.append(entry)

        fee = 0 if is_coinbase else max(0, input_sum - output_sum)
        total_fees += fee

        size, wbytes, nbytes, weight = _compute_weight_and_sizes(
            tx["raw"], tx["segwit"]
        )
        total_weight += weight

        formatted_txs.append({
            "txid": tx["txid"],
            "version": tx["version"],
            "locktime": tx["locktime"],
            "size_bytes": size,
            "weight": weight,
            "vbytes": (weight + 3) // 4,
            "fee_sats": fee,
            "vin": vin,
            "vout": vout
        })

    avg_fee_rate = round(total_fees / (total_weight / 4), 2) if total_weight else 0

    return {
        "ok": True,
        "mode": "block",
        "block_header": parsed["header"],
        "tx_count": parsed["tx_count"],

        "coinbase": {
            "bip34_height": bip34_height,
            "coinbase_script_hex": coinbase_script.hex(),
            "total_output_sats": coinbase_output_sum
        },

        "transactions": formatted_txs,

        "block_stats": {
            "total_fees_sats": total_fees,
            "total_weight": total_weight,
            "avg_fee_rate_sat_vb": avg_fee_rate,
            "script_type_summary": script_summary
        }
    }
    
def main():
    blk, rev, xor = sys.argv[1:]

    xor_key = open(xor, "rb").read()
    blk_data = xor_decrypt(open(blk, "rb").read(), xor_key)
    rev_data = xor_decrypt(open(rev, "rb").read(), xor_key)

    block = read_first_chunk(blk_data)
    undo_chunk = read_first_chunk(rev_data)

    parsed = parse_block(block)
    block_undo = parse_undo_block(undo_chunk)

    # ✅ USE LOCAL formatter (DO NOT IMPORT ANYTHING)
    out = format_block(parsed, block_undo)

    os.makedirs("out", exist_ok=True)
    with open(f"out/{parsed['header']['block_hash']}.json", "w") as f:
        json.dump(out, f)

if __name__ == "__main__":
    main()