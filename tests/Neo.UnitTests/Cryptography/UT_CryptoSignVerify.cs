// Copyright (C) 2015-2026 The Neo Project.
//
// UT_CryptoSignVerify.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Neo.Cryptography;
using Neo.Extensions.IO;
using Neo.Wallets;
using ECCurve = Neo.Cryptography.ECC.ECCurve;
using ECPoint = Neo.Cryptography.ECC.ECPoint;
using HashAlgorithm = Neo.Cryptography.HashAlgorithm;

namespace Neo.UnitTests.Cryptography;

[TestClass]
public class UT_CryptoSignVerify
{
    /// <summary>
    /// Cross-platform regression tests for PR #4506 sign/verify changes.
    /// These tests focus on places where different platforms may execute different crypto paths
    /// but must still produce the same verification outcome and exception behavior.
    /// </summary>
    private static readonly byte[] s_secp256r1Priv =
        "aabbccdd11223344556677889900112233445566778899001122334455667788".HexToBytes();

    private static readonly byte[] s_secp256k1Priv =
        "7177f0d04c79fa0b8c91fe90c1cf1d44772d1fba6e5eb9b281a22cd3aafb51fe".HexToBytes();

    private static ECPoint Secp256r1Pub => ECCurve.Secp256r1.G * s_secp256r1Priv;

    private static ECPoint Secp256k1Pub => ECCurve.Secp256k1.G * s_secp256k1Priv;

    private static string PlatformId =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "windows" :
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macos" :
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
        "unknown";

    private static byte[] GetSecp256k1FixedSha256Signature() =>
        ("b8cba1ff42304d74d083e87706058f59cdd4f755b995926d2cd80a734c5a3c37" +
         "e4583bfd4339ac762c1c91eee3782660a6baf62cd29e407eccd3da3e9de55a02").HexToBytes();

    private static byte[] GetSecp256k1FixedSha256CompressedPubKey() =>
        "03661b86d54eb3a8e7ea2399e0db36ab65753f95fff661da53ae0121278b881ad0".HexToBytes();

    private static byte[] GetKeccakVerifyMessage()
    {
        var messageBody = Encoding.UTF8.GetBytes("It's a small(er) world");
        return new byte[] { 0x19 }
            .Concat(Encoding.UTF8.GetBytes($"Ethereum Signed Message:\n{messageBody.Length}"))
            .Concat(messageBody)
            .ToArray();
    }

    private static byte[] GetKeccakVerifySignature() =>
        "9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76".HexToBytes()
            .Concat("139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793".HexToBytes())
            .ToArray();

    private static ECPoint GetKeccakVerifyPublicKey()
    {
        var privateKey = "1234567890123456789012345678901234567890123456789012345678901234".HexToBytes();
        return ECCurve.Secp256k1.G * privateKey;
    }

    private sealed record CreateEcdsaResult(
        string Outcome,
        string? ExceptionType = null,
        string? InnerExceptionType = null,
        bool? CacheSameInstance = null);

    private sealed record CrossPlatformReport(
        string Platform,
        string OsDescription,
        string Framework,
        string Sha256Hex,
        string Sha512Hex,
        string Keccak256Hex,
        bool VerifySecp256r1Sha256RoundTrip,
        bool VerifySecp256r1KeccakRoundTrip,
        bool VerifySecp256k1Sha256RoundTrip,
        bool VerifySecp256k1KeccakRoundTrip,
        bool VerifySecp256k1Sha256FixedCompressed,
        bool VerifySecp256k1Sha256FixedUncompressed,
        bool VerifySecp256k1KeccakFixed,
        CreateEcdsaResult CreateEcdsaSecp256r1,
        CreateEcdsaResult CreateEcdsaSecp256k1);

    private static CreateEcdsaResult CaptureCreateEcdsaResult(ECPoint pubkey)
    {
        try
        {
            var first = Crypto.CreateECDsa(pubkey);
            var second = Crypto.CreateECDsa(pubkey);
            return new CreateEcdsaResult("Success", CacheSameInstance: ReferenceEquals(first, second));
        }
        catch (ArgumentException ex)
        {
            return new CreateEcdsaResult(
                Outcome: "ArgumentException",
                ExceptionType: ex.GetType().FullName,
                InnerExceptionType: ex.InnerException?.GetType().FullName);
        }
    }

    private static string WriteCrossPlatformReport()
    {
        var sha256Input = Encoding.UTF8.GetBytes("neo-crypto-signverify-sha256");
        var sha512Input = "test"u8.ToArray();
        var keccakInput = Encoding.UTF8.GetBytes("abc");
        var secp256k1FixedCompressed = GetSecp256k1FixedSha256CompressedPubKey();
        var secp256k1FixedPoint = ECPoint.DecodePoint(secp256k1FixedCompressed, ECCurve.Secp256k1);
        var secp256k1FixedSignature = GetSecp256k1FixedSha256Signature();

        var report = new CrossPlatformReport(
            Platform: PlatformId,
            OsDescription: RuntimeInformation.OSDescription,
            Framework: RuntimeInformation.FrameworkDescription,
            Sha256Hex: Convert.ToHexString(Crypto.GetMessageHash(sha256Input, HashAlgorithm.SHA256)),
            Sha512Hex: Convert.ToHexString(Crypto.GetMessageHash(sha512Input, HashAlgorithm.SHA512)),
            Keccak256Hex: Convert.ToHexString(Crypto.GetMessageHash(keccakInput, HashAlgorithm.Keccak256)),
            VerifySecp256r1Sha256RoundTrip: Crypto.VerifySignature(
                sha256Input,
                Crypto.Sign(sha256Input, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.SHA256),
                Secp256r1Pub,
                HashAlgorithm.SHA256),
            VerifySecp256r1KeccakRoundTrip: Crypto.VerifySignature(
                keccakInput,
                Crypto.Sign(keccakInput, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.Keccak256),
                Secp256r1Pub,
                HashAlgorithm.Keccak256),
            VerifySecp256k1Sha256RoundTrip: Crypto.VerifySignature(
                sha256Input,
                Crypto.Sign(sha256Input, s_secp256k1Priv, ECCurve.Secp256k1, HashAlgorithm.SHA256),
                Secp256k1Pub,
                HashAlgorithm.SHA256),
            VerifySecp256k1KeccakRoundTrip: Crypto.VerifySignature(
                keccakInput,
                Crypto.Sign(keccakInput, s_secp256k1Priv, ECCurve.Secp256k1, HashAlgorithm.Keccak256),
                Secp256k1Pub,
                HashAlgorithm.Keccak256),
            VerifySecp256k1Sha256FixedCompressed: Crypto.VerifySignature(
                Encoding.Default.GetBytes("中文"),
                secp256k1FixedSignature,
                secp256k1FixedCompressed,
                ECCurve.Secp256k1,
                HashAlgorithm.SHA256),
            VerifySecp256k1Sha256FixedUncompressed: Crypto.VerifySignature(
                Encoding.Default.GetBytes("中文"),
                secp256k1FixedSignature,
                secp256k1FixedPoint.EncodePoint(false),
                ECCurve.Secp256k1,
                HashAlgorithm.SHA256),
            VerifySecp256k1KeccakFixed: Crypto.VerifySignature(
                GetKeccakVerifyMessage(),
                GetKeccakVerifySignature(),
                GetKeccakVerifyPublicKey(),
                HashAlgorithm.Keccak256),
            CreateEcdsaSecp256r1: CaptureCreateEcdsaResult(Secp256r1Pub),
            CreateEcdsaSecp256k1: CaptureCreateEcdsaResult(Secp256k1Pub));

        var workspace = Environment.GetEnvironmentVariable("GITHUB_WORKSPACE") ?? Directory.GetCurrentDirectory();
        var outputDir = Path.Combine(workspace, "TestResults", "cross-platform");
        Directory.CreateDirectory(outputDir);
        var outputPath = Path.Combine(outputDir, $"UT_CryptoSignVerify.{PlatformId}.json");
        File.WriteAllText(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        return outputPath;
    }

    #region GetMessageHash — deterministic inputs (no OS crypto)

    [TestMethod]
    public void GetMessageHash_Sha256_MatchesHelper_AndDeterministicAcrossPlatforms()
    {
        var msg = Encoding.UTF8.GetBytes("neo-crypto-signverify-sha256");
        var h = Crypto.GetMessageHash(msg, HashAlgorithm.SHA256);
        CollectionAssert.AreEqual(msg.Sha256(), h);
        using var sha = SHA256.Create();
        CollectionAssert.AreEqual(sha.ComputeHash(msg), h);
    }

    [TestMethod]
    public void GetMessageHash_Sha256_ReadOnlySpanOverload_MatchesHelper()
    {
        ReadOnlySpan<byte> msg = "neo-crypto-span"u8;
        CollectionAssert.AreEqual(msg.ToArray().Sha256(), Crypto.GetMessageHash(msg, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void GetMessageHash_Sha512_DeterministicAcrossPlatforms()
    {
        ReadOnlySpan<byte> msg = "test"u8;
        var h = Crypto.GetMessageHash(msg, HashAlgorithm.SHA512);
        using var sha = SHA512.Create();
        CollectionAssert.AreEqual(sha.ComputeHash(msg.ToArray()), h);
    }

    [TestMethod]
    public void GetMessageHash_Keccak256_MatchesHelper_AndDeterministicAcrossPlatforms()
    {
        var msg = Encoding.UTF8.GetBytes("abc");
        var h = Crypto.GetMessageHash(msg, HashAlgorithm.Keccak256);
        CollectionAssert.AreEqual(msg.Keccak256(), h);
    }

    [TestMethod]
    public void GetMessageHash_InvalidEnum_ThrowsNotSupportedException()
    {
        Assert.ThrowsExactly<NotSupportedException>(() =>
            Crypto.GetMessageHash(ReadOnlySpan<byte>.Empty, (HashAlgorithm)0xFF));
    }

    [TestMethod]
    public void GetMessageHash_ByteArrayOverload_InvalidEnum_Throws()
    {
        Assert.ThrowsExactly<NotSupportedException>(() =>
            Crypto.GetMessageHash(Array.Empty<byte>(), (HashAlgorithm)0xFE));
    }

    #endregion

    #region Sign — Secp256r1 native; Secp256k1 macOS uses BC, others use native (PR #4506)

    [TestMethod]
    public void Sign_Secp256r1_Sha256_RoundTrip_VerifyTrue()
    {
        var message = Encoding.UTF8.GetBytes("round-trip-secp256r1-sha256");
        var sig = Crypto.Sign(message, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
        Assert.AreEqual(64, sig.Length);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256r1Pub, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void Sign_Secp256r1_Keccak256_RoundTrip_UsesSignHashVerifyHashPath()
    {
        var message = Encoding.UTF8.GetBytes("round-trip-keccak");
        var sig = Crypto.Sign(message, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.Keccak256);
        Assert.AreEqual(64, sig.Length);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256r1Pub, HashAlgorithm.Keccak256));
    }

    [TestMethod]
    public void Sign_Secp256k1_Sha256_RoundTrip_MacOsBcVsNativeOs_InvariantVerifyTrue()
    {
        var message = Encoding.UTF8.GetBytes("k1-sha256");
        var sig = Crypto.Sign(message, s_secp256k1Priv, ECCurve.Secp256k1, HashAlgorithm.SHA256);
        Assert.AreEqual(64, sig.Length);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256k1Pub, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void Sign_Secp256k1_Keccak256_RoundTrip_MacOsBcVsNativeOs_InvariantVerifyTrue()
    {
        var message = Encoding.UTF8.GetBytes("k1-keccak");
        var sig = Crypto.Sign(message, s_secp256k1Priv, ECCurve.Secp256k1, HashAlgorithm.Keccak256);
        Assert.AreEqual(64, sig.Length);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256k1Pub, HashAlgorithm.Keccak256));
    }

    [TestMethod]
    public void Sign_DefaultCurveAndHash_IsSecp256r1_Sha256()
    {
        var message = new byte[] { 1, 2, 3 };
        var sig = Crypto.Sign(message, s_secp256r1Priv);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256r1Pub));
    }

    [TestMethod]
    public void Sign_Sha512_NotSupported_ForEcdsa()
    {
        Assert.ThrowsExactly<NotSupportedException>(() =>
            Crypto.Sign(Array.Empty<byte>(), s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.SHA512));
    }

    #endregion

    #region VerifySignature — fixed vectors: bool must match on all OS (BC vs native fork)

    [TestMethod]
    public void VerifySignature_WrongLength_ThrowsFormatException()
    {
        var message = new byte[] { 1 };
        var sig63 = new byte[63];
        var sig65 = new byte[65];
        var pub = Secp256r1Pub;
        Assert.ThrowsExactly<FormatException>(() => Crypto.VerifySignature(message, sig63, pub));
        Assert.ThrowsExactly<FormatException>(() => Crypto.VerifySignature(message, sig65, pub));
    }

    [TestMethod]
    public void VerifySignature_InvalidHashAlgorithm_ThrowsNotSupportedException()
    {
        var message = new byte[] { 1 };
        var sig = new byte[64];
        Assert.ThrowsExactly<NotSupportedException>(() =>
            Crypto.VerifySignature(message, sig, Secp256r1Pub, (HashAlgorithm)0xFD));
    }

    [TestMethod]
    public void VerifySignature_Sha512_ThrowsNotSupportedException()
    {
        var message = new byte[] { 1 };
        var sig = new byte[64];
        Assert.ThrowsExactly<NotSupportedException>(() =>
            Crypto.VerifySignature(message, sig, Secp256r1Pub, HashAlgorithm.SHA512));
    }

    [TestMethod]
    public void VerifySignature_TamperedSignature_ReturnsFalse()
    {
        var message = Encoding.UTF8.GetBytes("tamper-test");
        var sig = Crypto.Sign(message, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
        sig[0] ^= 0x01;
        Assert.IsFalse(Crypto.VerifySignature(message, sig, Secp256r1Pub, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void VerifySignature_WrongMessage_ReturnsFalse()
    {
        var message = Encoding.UTF8.GetBytes("message-a");
        var sig = Crypto.Sign(message, s_secp256r1Priv, ECCurve.Secp256r1, HashAlgorithm.SHA256);
        Assert.IsFalse(Crypto.VerifySignature(Encoding.UTF8.GetBytes("message-b"), sig, Secp256r1Pub, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void VerifySignature_Secp256k1_Sha256_RoundTrip_KnownVector()
    {
        byte[] message = "2d46a712699bae19a634563d74d04cc2da497b841456da270dccb75ac2f7c4e7".HexToBytes();
        var signature = Crypto.Sign(message, s_secp256k1Priv, ECCurve.Secp256k1, HashAlgorithm.SHA256);
        byte[] pubKey = ("04" + "fd0a8c1ce5ae5570fdd46e7599c16b175bf0ebdfe9c178f1ab848fb16dac74a5" +
            "d301b0534c7bcf1b3760881f0c420d17084907edd771e1c9c8e941bbf6ff9108").HexToBytes();
        Assert.IsTrue(Crypto.VerifySignature(message, signature, pubKey, ECCurve.Secp256k1, HashAlgorithm.SHA256));
    }

    /// <summary>
    /// Fixed signature bytes: must verify identically whether Secp256k1 uses BouncyCastle (macOS) or native ECDsa (elsewhere).
    /// </summary>
    [TestMethod]
    public void VerifySignature_Secp256k1_Sha256_FixedSignatureBytes_CrossPlatformBool()
    {
        var message = Encoding.Default.GetBytes("中文");
        var signature = ("b8cba1ff42304d74d083e87706058f59cdd4f755b995926d2cd80a734c5a3c37" +
            "e4583bfd4339ac762c1c91eee3782660a6baf62cd29e407eccd3da3e9de55a02").HexToBytes();
        var pubKeyCompressed = "03661b86d54eb3a8e7ea2399e0db36ab65753f95fff661da53ae0121278b881ad0".HexToBytes();
        Assert.IsTrue(Crypto.VerifySignature(message, signature, pubKeyCompressed, ECCurve.Secp256k1, HashAlgorithm.SHA256));
    }

    /// <summary>
    /// Same logical key as compressed form; PR #4506 Verify path must agree for both encodings.
    /// </summary>
    [TestMethod]
    public void VerifySignature_Secp256k1_FixedVector_CompressedAndUncompressedPubkey_BothTrue()
    {
        var message = Encoding.Default.GetBytes("中文");
        var signature = ("b8cba1ff42304d74d083e87706058f59cdd4f755b995926d2cd80a734c5a3c37" +
            "e4583bfd4339ac762c1c91eee3782660a6baf62cd29e407eccd3da3e9de55a02").HexToBytes();
        var pubCompressed = "03661b86d54eb3a8e7ea2399e0db36ab65753f95fff661da53ae0121278b881ad0".HexToBytes();
        var point = ECPoint.DecodePoint(pubCompressed, ECCurve.Secp256k1);
        var pubUncompressed = point.EncodePoint(false);
        Assert.IsTrue(Crypto.VerifySignature(message, signature, pubCompressed, ECCurve.Secp256k1, HashAlgorithm.SHA256));
        Assert.IsTrue(Crypto.VerifySignature(message, signature, pubUncompressed, ECCurve.Secp256k1, HashAlgorithm.SHA256));
    }

    /// <summary>
    /// Keccak256 + Secp256k1: SignHash/VerifyHash path; distinct from SHA256 SignData path (PR #4506).
    /// </summary>
    [TestMethod]
    public void VerifySignature_Secp256k1_Keccak256_FixedVector_FromEipStyleMessage()
    {
        var messageBody = Encoding.UTF8.GetBytes("It's a small(er) world");
        var message = new byte[] { 0x19 }
            .Concat(Encoding.UTF8.GetBytes($"Ethereum Signed Message:\n{messageBody.Length}"))
            .Concat(messageBody)
            .ToArray();
        var verifySig = "9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76".HexToBytes()
            .Concat("139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793".HexToBytes())
            .ToArray();
        var expectedPubKey = "1234567890123456789012345678901234567890123456789012345678901234".HexToBytes();
        var recoveredKey = ECCurve.Secp256k1.G * expectedPubKey;
        Assert.IsTrue(Crypto.VerifySignature(message, verifySig, recoveredKey, HashAlgorithm.Keccak256));
    }

    [TestMethod]
    public void VerifySignature_SpanOverload_EquivalentToEcPointOverload()
    {
        var message = Encoding.UTF8.GetBytes("span-overload");
        var sig = Crypto.Sign(message, s_secp256r1Priv);
        var pubBytes = Secp256r1Pub.EncodePoint(true);
        Assert.IsTrue(Crypto.VerifySignature(message, sig, pubBytes, ECCurve.Secp256r1, HashAlgorithm.SHA256));
        Assert.IsTrue(Crypto.VerifySignature(message, sig, Secp256r1Pub, HashAlgorithm.SHA256));
    }

    [TestMethod]
    public void VerifySignatureSpan_InvalidCompressedPubkey_ThrowsArgumentException()
    {
        var message = Encoding.UTF8.GetBytes("x");
        var sig = new byte[64];
        var wrongKey = new byte[33];
        wrongKey[0] = 0x03;
        for (int i = 1; i < 33; i++) wrongKey[i] = byte.MaxValue;
        Assert.ThrowsExactly<ArgumentException>(() =>
            Crypto.VerifySignature(message, sig, wrongKey, ECCurve.Secp256r1, HashAlgorithm.SHA256));
    }

    #endregion

    #region CreateECDsa — native cache (Secp256r1 / Secp256k1 when used); macOS Secp256k1 verify may bypass cache

    [TestMethod]
    public void CrossPlatform_Report_Pr4506CryptoBehavior()
    {
        var reportPath = WriteCrossPlatformReport();
        Assert.IsTrue(File.Exists(reportPath));
    }

    [TestMethod]
    public void CreateECDsa_Secp256r1_SamePublicKey_ReturnsSameCachedInstance()
    {
        var pub = Secp256r1Pub;
        var a = Crypto.CreateECDsa(pub);
        var b = Crypto.CreateECDsa(pub);
        Assert.AreSame(a, b);
    }

    [TestMethod]
    public void CreateECDsa_Secp256k1_SamePublicKey_ReturnsSameCachedInstance()
    {
        var pub = Secp256k1Pub;
        var a = Crypto.CreateECDsa(pub);
        var b = Crypto.CreateECDsa(pub);
        Assert.AreSame(a, b);
    }

    [TestMethod]
    public void CreateECDsa_InfinityPoint_Throws()
    {
        var infinity = new ECPoint();
        Assert.IsTrue(infinity.IsInfinity);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Crypto.CreateECDsa(infinity));
    }

    #endregion
}
