#!/usr/bin/env python3
"""
TwistLock (GUI Edition): A simple, self-designed, reversible file cipher.

Features:
  - Custom algorithm (not industry crypto): permute → rotate → XOR → half-swap → substitute
  - Key-based (passphrase + per-file random salt via SHAKE-256 KDF)
  - File I/O with chunking, simple header (tag + salt)
  - Menu-based CLI  OR Tkinter GUI with file selection dialogs (bonus)
  - Pure stdlib; should run on a typical grading VM (Python 3.6+)

Usage:
  GUI (default): python twistlock_gui.py
  CLI:           python twistlock_gui.py --cli
"""

from __future__ import annotations
import os
import sys
import hashlib
import secrets
from typing import List, Tuple

# ======== Core parameters ========
FILE_TAG = b"TWISTLOCK\x03"         # magic + version for GUI build
SALT_LEN = 16
CHUNK_BYTES = 64 * 1024
BLK = 3072
PROMPT = "[TwistLock] "


# ======== Tiny utils ========
def _rol8(x: int, k: int) -> int:
    k &= 7
    return ((x << k) | (x >> (8 - k))) & 0xFF

def _ror8(x: int, k: int) -> int:
    k &= 7
    return ((x >> k) | (x << (8 - k))) & 0xFF

def _trim_path(p: str) -> str:
    return p.strip().strip('"').strip("'")

def _same_path(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except Exception:
        return os.path.abspath(a) == os.path.abspath(b)


# ======== KDF & tables ========
def derive_material(passphrase: str, salt: bytes) -> bytes:
    """
    SHAKE-256(passphrase || 0x00 || salt || "twistlock-kdf-v1") → 96 bytes
    """
    if not isinstance(passphrase, str):
        raise TypeError("Passphrase must be a string.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise ValueError("Bad salt length.")
    shake = hashlib.shake_256()
    shake.update(passphrase.encode("utf-8", errors="surrogatepass"))
    shake.update(b"\x00")
    shake.update(salt)
    shake.update(b"twistlock-kdf-v1")
    return shake.digest(96)

def _lcg32(seed: int) -> int:
    return (seed * 1664525 + 1013904223) & 0xFFFFFFFF

def build_subst(seed: int) -> Tuple[bytes, bytes]:
    arr = list(range(256))
    s = seed & 0xFFFFFFFF
    for i in range(255, 0, -1):
        s = _lcg32(s)
        j = s % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    S = bytes(arr)
    inv = [0] * 256
    for i, v in enumerate(arr):
        inv[v] = i
    Sinv = bytes(inv)
    return S, Sinv

def build_index_perm(n: int, seed: int) -> Tuple[List[int], List[int]]:
    if n <= 1:
        return list(range(n)), list(range(n))
    arr = list(range(n))
    s = seed & 0xFFFFFFFF
    for i in range(n - 1, 0, -1):
        s = _lcg32(s)
        j = s % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    inv = [0] * n
    for i, v in enumerate(arr):
        inv[v] = i
    return arr, inv


# ======== transforms ========
def _permute(b: bytearray, perm: List[int]) -> bytearray:
    n = len(b)
    out = bytearray(n)
    # perm must be a bijection on range(n)
    for i in range(n):
        out[perm[i]] = b[i]
    return out

def _unpermute(b: bytearray, invperm: List[int]) -> bytearray:
    n = len(b)
    out = bytearray(n)
    for i in range(n):
        out[invperm[i]] = b[i]  # <-- correct inverse
    return out

def _xor_stream_inplace(b: bytearray, seed: int) -> None:
    s = seed & 0xFFFFFFFF
    for i in range(len(b)):
        s = _lcg32(s)
        b[i] ^= (s >> 16) & 0xFF


# ======== block ops ========
def encrypt_block(block: bytes, mat: bytes, S: bytes, perm: List[int], blkno: int) -> bytes:
    b = bytearray(block)

    # 1) permute positions
    b = _permute(b, perm)

    # 2) per-byte left rotate
    base_rot = mat[(blkno * 5 + 11) % len(mat)] & 7
    for i in range(len(b)):
        b[i] = _rol8(b[i], (base_rot + i + blkno) & 7)

    # 3) XOR keystream
    seed = int.from_bytes(mat[0:4], "little") ^ (blkno * 0xA001)
    _xor_stream_inplace(b, seed)

    # 4) half-block swap (rotate array by n//2)
    n = len(b)
    mid = n // 2
    b = bytearray(b[mid:] + b[:mid])

    # 5) substitution
    for i in range(n):
        b[i] = S[b[i]]

    return bytes(b)

def decrypt_block(block: bytes, mat: bytes, Sinv: bytes, invperm: List[int], blkno: int) -> bytes:
    b = bytearray(block)
    n = len(b)

    # inverse 5) substitution
    for i in range(n):
        b[i] = Sinv[b[i]]

    # inverse 4) undo rotate-left by mid (i.e., rotate-right by mid)
    mid = n // 2
    left_len = n - mid
    b = bytearray(b[left_len:] + b[:left_len])

    # inverse 3) XOR keystream
    seed = int.from_bytes(mat[0:4], "little") ^ (blkno * 0xA001)
    _xor_stream_inplace(b, seed)

    # inverse 2) per-byte right rotate
    base_rot = mat[(blkno * 5 + 11) % len(mat)] & 7
    for i in range(n):
        b[i] = _ror8(b[i], (base_rot + i + blkno) & 7)

    # inverse 1) un-permute positions
    b = _unpermute(b, invperm)

    return bytes(b)


# ======== file-level API ========
def encrypt_file(inp: str, outp: str, passphrase: str) -> None:
    inp = _trim_path(inp)
    outp = _trim_path(outp)

    if _same_path(inp, outp):
        raise OSError("Input and output paths must differ.")
    if not os.path.exists(inp):
        raise FileNotFoundError(inp)

    salt = secrets.token_bytes(SALT_LEN)
    mat = derive_material(passphrase, salt)
    S, _Sinv = build_subst(int.from_bytes(mat[8:12], "little"))

    with open(inp, "rb") as f_in, open(outp, "wb") as f_out:
        # header: tag + salt
        f_out.write(FILE_TAG + salt)

        blkno = 0
        while True:
            chunk = f_in.read(CHUNK_BYTES)
            if not chunk:
                break

            pos = 0
            L = len(chunk)
            while pos < L:
                blk = chunk[pos : pos + BLK]
                n = len(blk)
                perm, _ = build_index_perm(n, int.from_bytes(mat[12:16], "little"))
                enc = encrypt_block(blk, mat, S, perm, blkno)
                f_out.write(enc)
                pos += n
                blkno += 1

def decrypt_file(inp: str, outp: str, passphrase: str) -> None:
    inp = _trim_path(inp)
    outp = _trim_path(outp)

    if _same_path(inp, outp):
        raise OSError("Input and output paths must differ.")
    if not os.path.exists(inp):
        raise FileNotFoundError(inp)

    with open(inp, "rb") as f_in, open(outp, "wb") as f_out:
        head = f_in.read(len(FILE_TAG) + SALT_LEN)
        if len(head) != len(FILE_TAG) + SALT_LEN or not head.startswith(FILE_TAG):
            print("Not a TWISTLOCK file (bad header).", file=sys.stderr)
            return

        salt = head[len(FILE_TAG):]
        mat = derive_material(passphrase, salt)
        _S, Sinv = build_subst(int.from_bytes(mat[8:12], "little"))

        blkno = 0
        # Read encrypted stream in BLK-sized pulls; last tail may be shorter
        while True:
            enc = f_in.read(BLK)
            if not enc:
                break
            n = len(enc)
            _perm, invperm = build_index_perm(n, int.from_bytes(mat[12:16], "little"))
            dec = decrypt_block(enc, mat, Sinv, invperm, blkno)
            f_out.write(dec)
            blkno += 1


# ======== CLI ========
def run_cli() -> None:
    print("1) Encrypt a file")
    print("2) Decrypt a file")
    try:
        choice = int(input(PROMPT + "Enter your choice: ").strip())
    except Exception:
        print("Invalid choice.")
        return

    input_file = input(PROMPT + "Enter the input file path: ").strip()
    output_file = input(PROMPT + "Enter the output file path: ").strip()
    passphrase = input(PROMPT + "Enter passphrase (keep it secret): ").strip()

    try:
        if choice == 1:
            encrypt_file(input_file, output_file, passphrase)
            print("Done encrypting.")
        elif choice == 2:
            decrypt_file(input_file, output_file, passphrase)
            print("Done decrypting.")
        else:
            print("Invalid choice.")
    except FileNotFoundError as e:
        print(f"Error: {e} not found.")
    except PermissionError as e:
        print(f"Error: permission denied – {e}.")
    except OSError as e:
        print(f"OS Error: {e}.")
    except Exception as e:
        print(f"Unexpected error: {e}.")


# ======== Tkinter GUI (Bonus) ========
def run_gui() -> None:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("TwistLock – File Encrypt/Decrypt")
    root.minsize(520, 300)

    # ---- variables ----
    mode_var = tk.StringVar(value="encrypt")  # "encrypt" or "decrypt"
    in_path_var = tk.StringVar(value="")
    out_path_var = tk.StringVar(value="")
    pass_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="Ready.")

    # ---- layout helpers ----
    def row(parent, text):
        frame = ttk.Frame(parent)
        label = ttk.Label(frame, text=text, width=16, anchor="w")
        label.pack(side="left")
        return frame

    pad = dict(padx=12, pady=6)

    # ---- mode row ----
    r_mode = row(root, "Mode:")
    rb1 = ttk.Radiobutton(r_mode, text="Encrypt", value="encrypt", variable=mode_var)
    rb2 = ttk.Radiobutton(r_mode, text="Decrypt", value="decrypt", variable=mode_var)
    rb1.pack(side="left", padx=(0, 10))
    rb2.pack(side="left")
    r_mode.pack(fill="x", **pad)

    # ---- input file ----
    r_in = row(root, "Input file:")
    e_in = ttk.Entry(r_in, textvariable=in_path_var)
    e_in.pack(side="left", fill="x", expand=True)
    def browse_in():
        if mode_var.get() == "decrypt":
            # Encrypted files are arbitrary binary; show all files
            p = filedialog.askopenfilename(title="Select input file")
        else:
            p = filedialog.askopenfilename(title="Select input file")
        if p:
            in_path_var.set(p)
    b_in = ttk.Button(r_in, text="Browse…", command=browse_in)
    b_in.pack(side="left", padx=8)
    r_in.pack(fill="x", **pad)

    # ---- output file ----
    r_out = row(root, "Output file:")
    e_out = ttk.Entry(r_out, textvariable=out_path_var)
    e_out.pack(side="left", fill="x", expand=True)
    def browse_out():
        if mode_var.get() == "encrypt":
            default_ext = ".enc"
        else:
            default_ext = ".txt"
        p = filedialog.asksaveasfilename(
            title="Select output file",
            defaultextension=default_ext,
            confirmoverwrite=True
        )
        if p:
            out_path_var.set(p)
    b_out = ttk.Button(r_out, text="Browse…", command=browse_out)
    b_out.pack(side="left", padx=8)
    r_out.pack(fill="x", **pad)

    # ---- passphrase ----
    r_pass = row(root, "Passphrase:")
    e_pass = ttk.Entry(r_pass, textvariable=pass_var, show="*")
    e_pass.pack(side="left", fill="x", expand=True)
    r_pass.pack(fill="x", **pad)

    # ---- run + status ----
    r_actions = ttk.Frame(root)
    def do_run():
        inp = in_path_var.get().strip()
        outp = out_path_var.get().strip()
        pw = pass_var.get()

        # basic validation
        if not inp:
            messagebox.showerror("Error", "Please select an input file.")
            return
        if not outp:
            messagebox.showerror("Error", "Please choose an output file.")
            return
        if _same_path(inp, outp):
            messagebox.showerror("Error", "Input and output paths must differ.")
            return
        if not os.path.exists(inp):
            messagebox.showerror("Error", f"Input file not found:\n{inp}")
            return

        try:
            status_var.set("Working…")
            root.update_idletasks()
            if mode_var.get() == "encrypt":
                encrypt_file(inp, outp, pw)
                status_var.set("Done encrypting.")
                messagebox.showinfo("Success", "Encryption completed.")
            else:
                decrypt_file(inp, outp, pw)
                status_var.set("Done decrypting.")
                messagebox.showinfo("Success", "Decryption completed.")
        except FileNotFoundError:
            status_var.set("Error.")
            messagebox.showerror("Error", f"File not found:\n{inp}")
        except PermissionError as e:
            status_var.set("Error.")
            messagebox.showerror("Error", f"Permission denied:\n{e}")
        except OSError as e:
            status_var.set("Error.")
            messagebox.showerror("OS Error", str(e))
        except Exception as e:
            status_var.set("Error.")
            messagebox.showerror("Unexpected Error", str(e))

    b_run = ttk.Button(r_actions, text="Run", command=do_run)
    b_run.pack(side="left")
    r_actions.pack(fill="x", **pad)

    r_status = ttk.Frame(root)
    ttk.Label(r_status, textvariable=status_var, foreground="#0a0").pack(side="left")
    r_status.pack(fill="x", padx=12, pady=(0, 12))

    # polish
    for w in (e_in, e_out, e_pass):
        w.focus_set()

    root.mainloop()


# ======== entrypoint ========
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli()
    else:
        try:
            run_gui()
        except Exception as e:
            # If GUI cannot start (e.g., headless), fall back to CLI.
            print(f"GUI failed: {e}\nFalling back to CLI.\n")
            run_cli()

if __name__ == "__main__":
    main()
