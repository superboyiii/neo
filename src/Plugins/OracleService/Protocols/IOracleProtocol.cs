// Copyright (C) 2015-2025 The Neo Project.
//
// IOracleProtocol.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Neo.Network.P2P.Payloads;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Neo.Plugins.OracleService
{
    interface IOracleProtocol : IDisposable
    {
        void Configure();
        Task<(OracleResponseCode, string)> ProcessAsync(Uri uri, CancellationToken cancellation);
    }
}
