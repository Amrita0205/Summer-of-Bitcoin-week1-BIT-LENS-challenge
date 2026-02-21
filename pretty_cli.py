#!/usr/bin/env python3
"""
chain-lens — Bitcoin Transaction Decoder
Cyberpunk terminal aesthetic. No external dependencies.
"""

import sys
import json
import subprocess
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

R    = "\033[0m";  BOLD = "\033[1m";  DIM  = "\033[2m"
G1   = "\033[38;5;46m";   G2   = "\033[38;5;40m";  G3  = "\033[38;5;34m"
BTC  = "\033[38;5;214m";  GLD  = "\033[38;5;220m";  AMB = "\033[38;5;179m"
CYN  = "\033[38;5;51m";   BLU  = "\033[38;5;39m";   ICE = "\033[38;5;87m"
PRP  = "\033[38;5;135m";  LVN  = "\033[38;5;147m"
WHT  = "\033[38;5;255m";  GRY  = "\033[38;5;243m";  DRK = "\033[38;5;236m"
FOG  = "\033[38;5;240m";  RED  = "\033[38;5;196m";  ORG = "\033[38;5;202m"
BG_G = "\033[48;5;22m";   BG_R = "\033[48;5;52m"
BG_B = "\033[48;5;17m";   BG_DRK = "\033[48;5;233m"

NC = not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty())

def x(col, txt):
    return str(txt) if NC else col + str(txt) + R

def xb(col, txt):
    return str(txt) if NC else BOLD + col + str(txt) + R

def badge(txt, bg=BG_DRK, fg=WHT):
    if NC:
        return "[" + txt + "]"
    return BOLD + bg + fg + " " + txt + " " + R

W = 70

def ln(): print()

def div(char="─", col=DRK): print(x(col, char * W))

def sys_header(title, sub=""):
    ln()
    print(x(G3, "╔" + "═" * (W - 2) + "╗"))
    print(x(G3, "║") + xb(G1, title.center(W - 2)) + x(G3, "║"))
    if sub:
        print(x(G3, "║") + x(GLD, sub.center(W - 2)) + x(G3, "║"))
    print(x(G3, "╚" + "═" * (W - 2) + "╝"))
    ln()

def section(label, icon="◈"):
    ln()
    print(x(G2, icon + " ") + xb(GLD, label) + x(DRK, " " + "·" * (W - len(label) - 4)))
    print(x(DRK, "  " + "─" * (W - 2)))

def field(key, val, col=CYN):
    k = x(GRY, ("  " + key).ljust(20))
    print(k + x(DRK, " ▸ ") + x(col, str(val)))

def fmt_sats(n):
    if n == 0:
        return x(GRY, "0 sats")
    if n >= 100_000_000:
        quoted = "{:.8f} BTC".format(n / 1e8)
        return xb(GLD, quoted) + x(GRY, "  ({:,} sats)".format(n))
    return xb(GLD, "{:,}".format(n)) + x(GRY, " sats")

def fmt_rate(r):
    if r > 200: return xb(RED, str(r) + " sat/vB !! HIGH")
    if r > 50:  return xb(ORG, str(r) + " sat/vB")
    if r > 10:  return xb(AMB, str(r) + " sat/vB")
    return xb(G2, str(r) + " sat/vB")

def fmt_addr(addr):
    if not addr: return x(GRY, "—")
    if addr.startswith("bc1p"): return xb(BTC, addr)
    if addr.startswith("bc1"):  return xb(G1, addr)
    if addr.startswith("3"):    return xb(PRP, addr)
    return xb(BLU, addr)

def fmt_txid(txid):
    half = len(txid) // 2
    return x(ICE, txid[:half]) + xb(CYN, txid[half:])

def fmt_script(st):
    m = {
        "p2pkh":          (BLU, "P2PKH"),
        "p2sh":           (PRP, "P2SH"),
        "p2wpkh":         (G1,  "P2WPKH ⚡"),
        "p2wsh":          (G2,  "P2WSH ⚡"),
        "p2tr":           (BTC, "P2TR ◆"),
        "p2sh-p2wpkh":    (LVN, "P2SH-P2WPKH"),
        "p2sh-p2wsh":     (LVN, "P2SH-P2WSH"),
        "p2tr_keypath":   (BTC, "P2TR-KEYPATH ◆"),
        "p2tr_scriptpath":(GLD, "P2TR-SCRIPTPATH"),
        "op_return":      (GRY, "OP_RETURN"),
        "unknown":        (RED, "UNKNOWN ??"),
    }
    col, label = m.get(st, (GRY, st.upper()))
    return badge(label, BG_DRK, col)

def pct_bar(val, total, w=24):
    p = min(val / total, 1.0) if total else 0
    filled = round(p * w)
    return x(G2, "█" * filled) + x(DRK, "▒" * (w - filled)) + x(GRY, " {:.1f}%".format(p * 100))


def display_transaction(data):
    sys_header("[ CHAIN-LENS : TX DECODER ]", "Bitcoin Transaction Analysis System v1.0")

    section("TRANSACTION IDENTITY", "◈")
    ln()
    print("  " + x(GRY, "TXID  ") + fmt_txid(data["txid"]))
    if data.get("wtxid"):
        print("  " + x(GRY, "WTXID ") + x(DIM + ICE, data["wtxid"]))
    ln()

    sw_tag  = badge("SEGWIT ⚡", BG_G, G1) if data["segwit"] else badge("LEGACY", BG_DRK, GRY)
    net_tag = badge(data["network"].upper(), BG_B, CYN)
    rbf_tag = badge("RBF-ON", BG_R, RED) if data["rbf_signaling"] else badge("RBF-OFF", BG_DRK, GRY)
    print("  " + sw_tag + "  " + net_tag + "  " + rbf_tag)
    ln()
    print("  " + x(GRY, "VERSION  ") + xb(WHT, str(data["version"])) +
          "   " + x(GRY, "LOCKTIME ") + xb(WHT, str(data["locktime"])) +
          x(GRY, " [" + data["locktime_type"] + "]"))

    section("SIZE / WEIGHT / VBYTES", "◈")
    field("bytes",  str(data["size_bytes"]) + " B",  col=WHT)
    field("weight", str(data["weight"]) + " WU",     col=CYN)
    field("vbytes", str(data["vbytes"]) + " vB",     col=G1)
    if data.get("segwit_savings"):
        ss = data["segwit_savings"]
        ln()
        print("  " + x(GRY, "witness  ") + pct_bar(ss["witness_bytes"], ss["total_bytes"]) +
              x(GRY, "  " + str(ss["witness_bytes"]) + "B / " + str(ss["total_bytes"]) + "B"))
        if ss["savings_pct"] > 0:
            print("  " + x(G2, "⚡ SegWit saves ") + xb(G1, str(ss["savings_pct"]) + "% vs legacy"))

    section("VALUE FLOW", "◈")
    field("input",  fmt_sats(data["total_input_sats"]))
    field("output", fmt_sats(data["total_output_sats"]))
    print("  " + x(DRK, "  " + "╌" * 38))
    fee = data["fee_sats"]
    tin = data["total_input_sats"]
    pct = (fee / tin * 100) if tin else 0
    field("fee",  fmt_sats(fee) + x(GRY, "  ({:.2f}% burned)".format(pct)))
    field("rate", fmt_rate(data["fee_rate_sat_vb"]))
    ln()
    capped = min(data["fee_rate_sat_vb"], 200)
    print("  " + x(GRY, "rate bar ") + pct_bar(capped, 200, 30) + x(GRY, "  ceiling 200"))

    section("INPUTS  [" + str(len(data["vin"])) + "]", "▶")
    for i, inp in enumerate(data["vin"]):
        ln()
        print("  " + xb(G3, "┌── INPUT #" + str(i) + " ──") + "  " + fmt_script(inp["script_type"]))
        short = inp["txid"][:32] + "…"
        print("  " + x(G3, "│") + x(GRY, "  spent   ") + x(DIM + ICE, short) + x(CYN, " :" + str(inp["vout"])))
        if inp.get("address"):
            print("  " + x(G3, "│") + x(GRY, "  address ") + fmt_addr(inp["address"]))
        print("  " + x(G3, "│") + x(GRY, "  value   ") + fmt_sats(inp["prevout"]["value_sats"]))
        seq = inp["sequence"]
        seq_hex = "0x{:08x}".format(seq)
        seq_note = x(DIM, " final") if seq == 0xFFFFFFFF else (x(ORG, " signals RBF") if seq < 0xFFFFFFFE else "")
        print("  " + x(G3, "│") + x(GRY, "  seq     ") + x(FOG, seq_hex) + seq_note)
        wit = inp.get("witness", [])
        if wit and any(wit):
            print("  " + x(G3, "│") + x(GRY, "  witness ") + x(G2, str(len(wit)) + " item(s)"))
        rtl = inp.get("relative_timelock", {})
        if rtl.get("enabled"):
            print("  " + x(G3, "│") + x(AMB, "  ⏳ rel-timelock: " + str(rtl.get("value")) + " " + str(rtl.get("type", ""))))
        print("  " + x(G3, "└" + "─" * 20))

    section("OUTPUTS  [" + str(len(data["vout"])) + "]", "▶")
    for out in data["vout"]:
        ln()
        dust = out["value_sats"] < 546 and out["script_type"] != "op_return"
        dust_tag = "  " + badge("DUST!", BG_R, RED) if dust else ""
        print("  " + xb(BLU, "┌── OUTPUT #" + str(out["n"]) + " ──") + "  " + fmt_script(out["script_type"]) + dust_tag)
        print("  " + x(BLU, "│") + x(GRY, "  value   ") + fmt_sats(out["value_sats"]))
        if out.get("address"):
            print("  " + x(BLU, "│") + x(GRY, "  address ") + fmt_addr(out["address"]))
        if out["script_type"] == "op_return":
            utf8 = out.get("op_return_data_utf8")
            if utf8:
                quoted = '"' + utf8 + '"'
                print("  " + x(BLU, "│") + x(GRY, "  data    ") + xb(GLD, quoted))
            else:
                hexval = out.get("op_return_data_hex", "")
                print("  " + x(BLU, "│") + x(GRY, "  hex     ") + x(DIM, hexval))
            proto = out.get("op_return_protocol", "unknown")
            if proto != "unknown":
                print("  " + x(BLU, "│") + x(GRY, "  proto   ") + xb(CYN, proto.upper()))
        print("  " + x(BLU, "└" + "─" * 20))

    warnings = data.get("warnings", [])
    if warnings:
        section("WARNINGS", "⚠")
        wc = {"HIGH_FEE": RED, "DUST_OUTPUT": ORG, "RBF_SIGNALING": AMB, "UNKNOWN_OUTPUT_SCRIPT": RED}
        for w in warnings:
            ln()
            col = wc.get(w["code"], AMB)
            print("  " + badge("!! " + w["code"], BG_R, col))
            print("  " + x(GRY, "   " + w.get("message", "")))
        ln()

    ln()
    div("═", G3)
    summary = ("  CHAIN-LENS  ·  " + data["network"] + "  ·  " +
               str(len(data["vin"])) + "→" + str(len(data["vout"])) + "  ·  " +
               str(data["vbytes"]) + " vB  ·  " + str(data["fee_sats"]) + " sats fee")
    print(x(G3, "║") + x(GRY, summary.ljust(W - 2)) + x(G3, "║"))
    div("═", G3)
    ln()


def display_block(data):
    sys_header("[ CHAIN-LENS : BLOCK DECODER ]", "Bitcoin Block Analysis System v1.0")
    h = data.get("block_header", {})
    section("BLOCK HEADER", "◈")
    ln()
    print("  " + x(GRY, "HASH  ") + fmt_txid(h.get("block_hash", "?")))
    print("  " + x(GRY, "PREV  ") + x(DIM + ICE, h.get("prev_block_hash", "?")))
    ln()
    field("version",   h.get("version", "?"),  col=WHT)
    field("timestamp", h.get("timestamp", "?"), col=CYN)
    field("bits",      h.get("bits", "?"),      col=GRY)
    field("nonce",     h.get("nonce", "?"),     col=GRY)
    ln()
    mv = h.get("merkle_root_valid", False)
    mv_tag = badge("MERKLE ✓ VALID", BG_G, G1) if mv else badge("MERKLE ✗ INVALID", BG_R, RED)
    print("  " + mv_tag)
    print("  " + x(DIM + ICE, "  " + h.get("merkle_root", "?")))

    section("BLOCK STATS", "◈")
    stats = data.get("block_stats", {})
    field("tx count",   data.get("tx_count", 0),  col=GLD)
    field("total fees", fmt_sats(stats.get("total_fees_sats", 0)))
    field("weight",     str(stats.get("total_weight", 0)) + " WU", col=CYN)
    field("avg rate",   str(stats.get("avg_fee_rate_sat_vb", 0)) + " sat/vB", col=G1)

    stypes = stats.get("script_type_summary", {})
    if stypes:
        ln()
        print("  " + x(GRY, "script type distribution:"))
        mx = max(stypes.values()) if stypes else 1
        for st, cnt in sorted(stypes.items(), key=lambda i: -i[1]):
            print("    " + fmt_script(st) + "  " + pct_bar(cnt, mx, 18) + x(GRY, "  " + str(cnt)))

    cb = data.get("coinbase", {})
    if cb:
        section("COINBASE TX", "◈")
        field("bip34 height", cb.get("bip34_height", "?"), col=GLD)
        field("block reward", fmt_sats(cb.get("total_output_sats", 0)))
        sh = cb.get("coinbase_script_hex", "")
        if sh:
            print("  " + x(GRY, "  script   ▸ ") + x(DIM + GRY, sh[:60] + ("…" if len(sh) > 60 else "")))

    ln()
    div("═", G3)
    summary = ("  CHAIN-LENS  ·  block  ·  " + str(data.get("tx_count", 0)) +
               " txs  ·  " + str(stats.get("total_fees_sats", 0)) + " sats fees")
    print(x(G3, "║") + x(GRY, summary.ljust(W - 2)) + x(G3, "║"))
    div("═", G3)
    ln()


def run_tx(fixture):
    r = subprocess.run(["python3", os.path.join(SCRIPT_DIR, "analyzer.py"), fixture],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(x(RED, "error: " + r.stderr), file=sys.stderr); sys.exit(1)
    return json.loads(r.stdout)

def run_block(blk, rev, xor):
    r = subprocess.run(["python3", os.path.join(SCRIPT_DIR, "block_analyzer.py"), blk, rev, xor],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(x(RED, "error: " + r.stderr), file=sys.stderr); sys.exit(1)
    return json.loads(r.stdout)

def main():
    args = sys.argv[1:]
    if not args:
        print(x(RED, "Usage: pretty_cli.py --pretty <fixture.json>"))
        sys.exit(1)
    if args[0] == "--pretty" and len(args) >= 2:
        if not os.path.exists(args[1]):
            print(x(RED, "File not found: " + args[1])); sys.exit(1)
        data = run_tx(args[1])
        if not data.get("ok"):
            print(x(RED, "Error: " + data.get("error", {}).get("message", "?"))); sys.exit(1)
        display_transaction(data)
    elif args[0] == "--pretty-block" and len(args) >= 4:
        data = run_block(args[1], args[2], args[3])
        if not data.get("ok"):
            print(x(RED, "Error: " + data.get("error", {}).get("message", "?"))); sys.exit(1)
        display_block(data)
    else:
        print(x(RED, "Unknown: " + " ".join(args))); sys.exit(1)

if __name__ == "__main__":
    main()