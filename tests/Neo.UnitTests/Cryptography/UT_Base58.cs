// Copyright (C) 2015-2025 The Neo Project.
//
// UT_Base58.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Neo.Cryptography;
using Neo.Extensions;
using System;
using System.Collections.Generic;

namespace Neo.UnitTests.Cryptography
{
    [TestClass]
    public class UT_Base58
    {
        [TestMethod]
        public void TestEncodeDecode()
        {
            var bitcoinTest = new Dictionary<string, string>()
            {
                // Tests from https://github.com/bitcoin/bitcoin/blob/46fc4d1a24c88e797d6080336e3828e45e39c3fd/src/test/data/base58_encode_decode.json
                {"", ""},
                {"61", "2g"},
                {"626262", "a3gV"},
                {"636363", "aPEr"},
                {"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
                {"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
                {"516b6fcd0f", "ABnLTmg"},
                {"bf4f89001e670274dd", "3SEo3LWLoPntC"},
                {"572e4794", "3EFU7m"},
                {"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
                {"10c8511e", "Rt5zm"},
                {"00000000000000000000", "1111111111"},
                {
                    "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5",
                    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                },
                {
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2" +
                    "c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758" +
                    "595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848" +
                    "5868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1" +
                    "b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcddd" +
                    "edfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                    "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEw" +
                    "P8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boW" +
                    "wCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1g" +
                    "YBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY"
                },
                // Extra tests
                {"00", "1"},
                {"00010203040506070809", "1kA3B2yGe2z4"},
            };

            foreach (var entry in bitcoinTest)
            {
                Assert.AreEqual(entry.Value, Base58.Encode(entry.Key.HexToBytes()));
                CollectionAssert.AreEqual(entry.Key.HexToBytes(), Base58.Decode(entry.Value));
            }

            var invalidBase58 = new string[] { "0", "O", "I", "l", "+", "/" };
            foreach (var s in invalidBase58)
            {
                var action = new Action(() => Base58.Decode(s));
                Assert.ThrowsExactly<FormatException>(action);
            }
        }
    }
}
