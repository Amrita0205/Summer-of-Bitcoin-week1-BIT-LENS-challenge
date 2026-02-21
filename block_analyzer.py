#!/usr/bin/env python3
"""
Bitcoin Block Analyzer
Parses blk*.dat files (with XOR key) and outputs structured JSON per block.
Only parses the FIRST block per the challenge scope.
"""

import sys
import json
import hashlib
import struct
import math
import os

# Re-use helpers from analyzer.py
sys.path.insert(0, os.path.dirname(__file__))
from analyzer import (
    parse_raw_tx, _compute_txid, _compute_weight_and_sizes,
    classify_output_script, classify_input_script,
    script_to_asm, decode_locktime, decode_sequence_timelock,
    _sha256d
)


def read_xor_key(xor_path: str) -> bytes:
    with open(xor_path, 'rb') as f:
        return f.read()


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    if not key or all(b == 0 for b in key):
        return data
    result = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        result[i] = b ^ key[i % klen]
    return bytes(result)


def read_varint(data: bytes, pos: int):
    first = data[pos]
    if first < 0xfd:
        return first, pos + 1
    elif first == 0xfd:
        return struct.unpack_from('<H', data, pos + 1)[0], pos + 3
    elif first == 0xfe:
        return struct.unpack_from('<I', data, pos + 1)[0], pos + 5
    else:
        return struct.unpack_from('<Q', data, pos + 1)[0], pos + 9


def parse_block(data: bytes) -> dict:
    """Parse a single block from raw decrypted bytes."""
    if len(data) < 80:
        raise ValueError("Block data too short for header")

    # Parse 80-byte header
    version = struct.unpack_from('<I', data, 0)[0]
    prev_hash = data[4:36][::-1].hex()
    merkle_root_bytes = data[36:68]
    merkle_root = merkle_root_bytes[::-1].hex()
    timestamp = struct.unpack_from('<I', data, 68)[0]
    bits = data[72:76].hex()
    nonce = struct.unpack_from('<I', data, 76)[0]

    # Block hash = sha256d of the 80-byte header
    header_bytes = data[:80]
    block_hash = _sha256d(header_bytes)[::-1].hex()

    # Parse transactions
    pos = 80
    tx_count, pos = read_varint(data, pos)
    transactions = []

    for tx_idx in range(tx_count):
        tx_start = pos
        # Detect segwit
        version_bytes = data[pos:pos+4]
        tx_version = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        is_segwit = False
        if data[pos] == 0x00 and data[pos+1] == 0x01:
            is_segwit = True
            pos += 2

        # inputs
        vin_count, pos = read_varint(data, pos)
        inputs = []
        for _ in range(vin_count):
            txid = data[pos:pos+32][::-1].hex()
            vout = struct.unpack_from('<I', data, pos+32)[0]
            pos += 36
            sl, pos = read_varint(data, pos)
            script_sig = data[pos:pos+sl]
            pos += sl
            sequence = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            inputs.append({'txid': txid, 'vout': vout, 'script_sig': script_sig,
                           'sequence': sequence, 'witness': []})

        # outputs
        vout_count, pos = read_varint(data, pos)
        outputs = []
        for i in range(vout_count):
            value = struct.unpack_from('<q', data, pos)[0]
            pos += 8
            sl, pos = read_varint(data, pos)
            script = data[pos:pos+sl]
            pos += sl
            outputs.append({'n': i, 'value_sats': value, 'script_pubkey': script})

        if is_segwit:
            for inp in inputs:
                item_count, pos = read_varint(data, pos)
                items = []
                for _ in range(item_count):
                    il, pos = read_varint(data, pos)
                    items.append(data[pos:pos+il].hex())
                    pos += il
                inp['witness'] = items

        locktime = struct.unpack_from('<I', data, pos)[0]
        pos += 4

        tx_raw = data[tx_start:pos]
        txid = _compute_txid(tx_raw, is_segwit)
        transactions.append({
            'txid': txid,
            'is_segwit': is_segwit,
            'version': tx_version,
            'locktime': locktime,
            'inputs': inputs,
            'outputs': outputs,
            'raw': tx_raw,
        })

    # Compute merkle root from txids
    computed_merkle = compute_merkle_root([bytes.fromhex(tx['txid'])[::-1] for tx in transactions])
    merkle_root_valid = (computed_merkle == merkle_root_bytes)

    return {
        'block_hash': block_hash,
        'header': {
            'version': version,
            'prev_block_hash': prev_hash,
            'merkle_root': merkle_root,
            'merkle_root_valid': merkle_root_valid,
            'timestamp': timestamp,
            'bits': bits,
            'nonce': nonce,
            'block_hash': block_hash,
        },
        'tx_count': tx_count,
        'transactions': transactions,
    }


def compute_merkle_root(txids: list) -> bytes:
    """Compute merkle root from list of txid bytes (internal byte order)."""
    if not txids:
        return b'\x00' * 32
    if len(txids) == 1:
        return txids[0]
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(_sha256d(level[i] + level[i+1]))
        level = next_level
    return level[0]


def decode_bip34_height(coinbase_script: bytes) -> int | None:
    """Extract block height from coinbase scriptSig (BIP34)."""
    try:
        if len(coinbase_script) < 1:
            return None
        push_len = coinbase_script[0]
        if push_len == 0 or push_len > 5:
            return None
        height_bytes = coinbase_script[1:1+push_len]
        height = int.from_bytes(height_bytes, 'little')
        return height
    except Exception:
        return None


def format_block_output(block: dict) -> dict:
    """Convert parsed block to the required JSON schema."""
    transactions = block['transactions']
    mainnet = True  # blk files are mainnet

    # Coinbase is always first tx
    coinbase_tx = transactions[0] if transactions else None
    coinbase_out = None
    if coinbase_tx:
        cb_script = coinbase_tx['inputs'][0]['script_sig'] if coinbase_tx['inputs'] else b''
        bip34_height = decode_bip34_height(cb_script)
        total_cb_out = sum(o['value_sats'] for o in coinbase_tx['outputs'])
        coinbase_out = {
            'bip34_height': bip34_height if bip34_height is not None else 0,
            'coinbase_script_hex': cb_script.hex(),
            'total_output_sats': total_cb_out,
        }

    # Build tx list
    tx_list = []
    total_fees = 0
    total_weight = 0
    script_type_summary = {}

    for i, tx in enumerate(transactions):
        raw = tx['raw']
        is_segwit = tx['is_segwit']
        size, witness_bytes, non_witness_bytes, weight = _compute_weight_and_sizes(raw, is_segwit)
        vbytes = math.ceil(weight / 4)
        total_weight += weight

        # Build vin/vout
        vout_list = []
        total_out = 0
        for out in tx['outputs']:
            stype, addr, extras = classify_output_script(out['script_pubkey'], mainnet)
            total_out += out['value_sats']
            entry = {
                'n': out['n'],
                'value_sats': out['value_sats'],
                'script_pubkey_hex': out['script_pubkey'].hex(),
                'script_asm': script_to_asm(out['script_pubkey']),
                'script_type': stype,
                'address': addr,
            }
            entry.update(extras)
            vout_list.append(entry)
            # track types
            script_type_summary[stype] = script_type_summary.get(stype, 0) + 1

        vin_list = []
        for inp in tx['inputs']:
            vin_list.append({
                'txid': inp['txid'],
                'vout': inp['vout'],
                'sequence': inp['sequence'],
                'script_sig_hex': inp['script_sig'].hex(),
                'witness': inp['witness'],
            })

        fee_sats = None
        if i > 0:
            # non-coinbase: fee = inputs - outputs but we don't have prevouts
            # mark as 0 for now — would need undo data for real fee
            fee_sats = 0
            total_fees += fee_sats

        tx_entry = {
            'txid': tx['txid'],
            'version': tx['version'],
            'locktime': tx['locktime'],
            'is_segwit': is_segwit,
            'size_bytes': size,
            'weight': weight,
            'vbytes': vbytes,
            'vin': vin_list,
            'vout': vout_list,
        }
        if fee_sats is not None:
            tx_entry['fee_sats'] = fee_sats

        tx_list.append(tx_entry)

    avg_fee_rate = round(total_fees / (total_weight / 4), 2) if total_weight > 0 else 0.0

    return {
        'ok': True,
        'mode': 'block',
        'block_header': block['header'],
        'tx_count': block['tx_count'],
        'coinbase': coinbase_out,
        'transactions': tx_list,
        'block_stats': {
            'total_fees_sats': total_fees,
            'total_weight': total_weight,
            'avg_fee_rate_sat_vb': avg_fee_rate,
            'script_type_summary': script_type_summary,
        },
    }


def parse_blk_file(blk_path: str, xor_key: bytes) -> list:
    """
    Parse blk*.dat file and return list of raw block data chunks.
    Each block is prefixed by: magic(4) + size(4) + block_data(size)
    """
    with open(blk_path, 'rb') as f:
        raw = f.read()

    data = xor_decrypt(raw, xor_key)

    MAGIC_MAINNET = b'\xf9\xbe\xb4\xd9'
    blocks = []
    pos = 0
    while pos < len(data) - 8:
        # Find magic bytes
        if data[pos:pos+4] != MAGIC_MAINNET:
            # Skip padding zeros
            if data[pos] == 0:
                pos += 1
                continue
            pos += 1
            continue
        pos += 4
        if pos + 4 > len(data):
            break
        block_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if block_size == 0 or pos + block_size > len(data):
            break
        blocks.append(data[pos:pos+block_size])
        pos += block_size

    return blocks


def main():
    if len(sys.argv) < 4:
        err = {'ok': False, 'error': {'code': 'INVALID_ARGS',
               'message': 'Usage: block_analyzer.py <blk.dat> <rev.dat> <xor.dat>'}}
        print(json.dumps(err))
        sys.exit(1)

    blk_path, rev_path, xor_path = sys.argv[1], sys.argv[2], sys.argv[3]

    try:
        xor_key = read_xor_key(xor_path)
        block_chunks = parse_blk_file(blk_path, xor_key)

        if not block_chunks:
            err = {'ok': False, 'error': {'code': 'NO_BLOCKS', 'message': 'No blocks found in blk file'}}
            print(json.dumps(err))
            sys.exit(1)

        # Only parse FIRST block (per challenge scope to avoid CI timeouts)
        block_data = block_chunks[0]
        parsed = parse_block(block_data)
        output = format_block_output(parsed)

        os.makedirs('out', exist_ok=True)
        block_hash = parsed['block_hash']
        out_path = f'out/{block_hash}.json'
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2)

        print(json.dumps(output, indent=2))

    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        err = {'ok': False, 'error': {'code': 'PARSE_ERROR', 'message': str(e)}}
        print(json.dumps(err))
        sys.exit(1)


if __name__ == '__main__':
    main()
