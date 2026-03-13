# Cross-Platform Verify (PR #4449)

Run with the **same seed** on Windows and Linux, then compare the output to verify that `VerifySignature`, `VerifyWithEd25519`, and `VerifyWithECDsa` behave identically on both platforms.

## Usage

### 1. Run with a seed (recommended: use scripts to save output)

**Windows (PowerShell or CMD):**
```bat
cd tests\CrossPlatformVerify
run_cross_platform_verify.bat 12345 results_windows.txt
```

**Linux / Git Bash:**
```bash
cd tests/CrossPlatformVerify
chmod +x run_cross_platform_verify.sh
./run_cross_platform_verify.sh 12345 results_linux.txt
```

### 2. Direct dotnet run (no output file)

```bash
cd tests/CrossPlatformVerify
dotnet run -- 12345
```

- The first argument is the **seed** (integer); default is `12345` if omitted.
- The same seed produces the same random messages and keys, so output from Windows and Linux with the same seed should match.

### 3. Compare results

After saving output from both systems to files, compare with diff:

```bash
diff results_windows.txt results_linux.txt
```

- No output means the files are identical.
- Any difference is printed so you can track down cross-platform inconsistencies.

## Output format

- First line: `SEED=<seed>`
- Second line: `OS=<current OS info>`
- Each following line: `CASE|<id>|<case_name>|<True|False|Exception:...>`
- Last line: `DONE`

Cases cover the APIs changed in the PR:

- ECDSA: Secp256r1/Secp256k1 + SHA256/Keccak256 (valid signature → True, tampered message → False)
- `Crypto.VerifySignature(message, signature, pubkey_bytes, curve, hash)` usage
- Ed25519: valid signature and tampered-message verification
