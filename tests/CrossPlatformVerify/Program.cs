// Cross-platform verification script for PR #4449 (VerifySignature / VerifyWithEd25519 / VerifyWithECDsa).
// Run with same seed on Windows and Linux, then diff the output to ensure identical behavior.
// Usage: dotnet run [seed]
// Example: dotnet run 12345

using System;
using System.Text;
using Neo.Cryptography;
using Neo.Cryptography.ECC;
using ECCurve = Neo.Cryptography.ECC.ECCurve;
using ECPoint = Neo.Cryptography.ECC.ECPoint;

int seed = args.Length > 0 && int.TryParse(args[0], out int s) ? s : 12345;
var r = new Random(seed);

Console.WriteLine($"SEED={seed}");
Console.WriteLine($"OS={Environment.OSVersion}");
Console.OutputEncoding = Encoding.UTF8;

int caseId = 0;

// ---- ECDSA: Secp256r1 + SHA256 ----
byte[] msg = Fill(r, 8 + (r.Next() % 128));
byte[] priv = Fill(r, 32);
RunCase("ECDSA_Secp256r1_SHA256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256r1.G * priv;
    return Crypto.VerifySignature(msg, sig, pub, HashAlgorithm.SHA256);
});
RunCase("ECDSA_Secp256r1_SHA256_invalid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256r1.G * priv;
    byte[] badMsg = (byte[])msg.Clone();
    if (badMsg.Length > 0) badMsg[0] ^= 0xFF;
    return Crypto.VerifySignature(badMsg, sig, pub, HashAlgorithm.SHA256);
});

// ---- ECDSA: Secp256k1 + SHA256 ----
msg = Fill(r, 8 + (r.Next() % 128));
priv = Fill(r, 32);
RunCase("ECDSA_Secp256k1_SHA256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256k1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256k1.G * priv;
    return Crypto.VerifySignature(msg, sig, pub, HashAlgorithm.SHA256);
});
RunCase("ECDSA_Secp256k1_SHA256_invalid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256k1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256k1.G * priv;
    byte[] badMsg = (byte[])msg.Clone();
    if (badMsg.Length > 0) badMsg[0] ^= 0xFF;
    return Crypto.VerifySignature(badMsg, sig, pub, HashAlgorithm.SHA256);
});

// ---- ECDSA: Secp256r1 + Keccak256 ----
msg = Fill(r, 8 + (r.Next() % 128));
priv = Fill(r, 32);
RunCase("ECDSA_Secp256r1_Keccak256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256r1, HashAlgorithm.Keccak256);
    ECPoint pub = ECCurve.Secp256r1.G * priv;
    return Crypto.VerifySignature(msg, sig, pub, HashAlgorithm.Keccak256);
});
RunCase("ECDSA_Secp256r1_Keccak256_invalid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256r1, HashAlgorithm.Keccak256);
    ECPoint pub = ECCurve.Secp256r1.G * priv;
    byte[] badMsg = (byte[])msg.Clone();
    if (badMsg.Length > 0) badMsg[0] ^= 0xFF;
    return Crypto.VerifySignature(badMsg, sig, pub, HashAlgorithm.Keccak256);
});

// ---- ECDSA: Secp256k1 + Keccak256 ----
msg = Fill(r, 8 + (r.Next() % 128));
priv = Fill(r, 32);
RunCase("ECDSA_Secp256k1_Keccak256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256k1, HashAlgorithm.Keccak256);
    ECPoint pub = ECCurve.Secp256k1.G * priv;
    return Crypto.VerifySignature(msg, sig, pub, HashAlgorithm.Keccak256);
});
RunCase("ECDSA_Secp256k1_Keccak256_invalid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256k1, HashAlgorithm.Keccak256);
    ECPoint pub = ECCurve.Secp256k1.G * priv;
    byte[] badMsg = (byte[])msg.Clone();
    if (badMsg.Length > 0) badMsg[0] ^= 0xFF;
    return Crypto.VerifySignature(badMsg, sig, pub, HashAlgorithm.Keccak256);
});

// ---- VerifySignature(byte[] pubkey, curve) overload (used by CryptoLib) ----
msg = Fill(r, 16);
priv = Fill(r, 32);
RunCase("VerifySignature_pubkey_bytes_Secp256r1_SHA256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256r1.G * priv;
    byte[] pubBytes = pub.EncodePoint(true);
    return Crypto.VerifySignature(msg, sig, pubBytes, ECCurve.Secp256r1, HashAlgorithm.SHA256);
});
RunCase("VerifySignature_pubkey_bytes_Secp256k1_SHA256_valid", () =>
{
    byte[] sig = Crypto.Sign(msg, priv, ECCurve.Secp256k1, HashAlgorithm.SHA256);
    ECPoint pub = ECCurve.Secp256k1.G * priv;
    byte[] pubBytes = pub.EncodePoint(true);
    return Crypto.VerifySignature(msg, sig, pubBytes, ECCurve.Secp256k1, HashAlgorithm.SHA256);
});

// ---- Ed25519 ----
byte[] edPriv = Fill(r, 32);
msg = Fill(r, 8 + (r.Next() % 128));
RunCase("Ed25519_valid", () =>
{
    byte[] sig = Ed25519.Sign(edPriv, msg);
    byte[] edPub = Ed25519.GetPublicKey(edPriv);
    return Ed25519.Verify(edPub, msg, sig);
});
RunCase("Ed25519_invalid", () =>
{
    byte[] sig = Ed25519.Sign(edPriv, msg);
    byte[] edPub = Ed25519.GetPublicKey(edPriv);
    byte[] badMsg = (byte[])msg.Clone();
    if (badMsg.Length > 0) badMsg[0] ^= 0xFF;
    return Ed25519.Verify(edPub, badMsg, sig);
});

Console.WriteLine("DONE");

void RunCase(string name, Func<bool> action)
{
    caseId++;
    try
    {
        bool result = action();
        Console.WriteLine($"CASE|{caseId}|{name}|{result}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"CASE|{caseId}|{name}|Exception:{ex.GetType().Name}:{ex.Message}");
    }
}

static byte[] Fill(Random r, int len)
{
    var b = new byte[len];
    r.NextBytes(b);
    return b;
}
