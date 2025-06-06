// Copyright (C) 2015-2025 The Neo Project.
//
// GasToken.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Neo.Cryptography.ECC;
using Neo.Network.P2P.Payloads;

namespace Neo.SmartContract.Native
{
    /// <summary>
    /// Represents the GAS token in the NEO system.
    /// </summary>
    public sealed class GasToken : FungibleToken<AccountState>
    {
        public override string Symbol => "GAS";
        public override byte Decimals => 8;

        internal GasToken()
        {
        }

        internal override ContractTask InitializeAsync(ApplicationEngine engine, Hardfork? hardfork)
        {
            if (hardfork == ActiveIn)
            {
                UInt160 account = Contract.GetBFTAddress(engine.ProtocolSettings.StandbyValidators);
                return Mint(engine, account, engine.ProtocolSettings.InitialGasDistribution, false);
            }
            return ContractTask.CompletedTask;
        }

        internal override async ContractTask OnPersistAsync(ApplicationEngine engine)
        {
            long totalNetworkFee = 0;
            foreach (Transaction tx in engine.PersistingBlock.Transactions)
            {
                await Burn(engine, tx.Sender, tx.SystemFee + tx.NetworkFee);
                totalNetworkFee += tx.NetworkFee;

                // Reward for NotaryAssisted attribute will be minted to designated notary nodes
                // by Notary contract.
                var notaryAssisted = tx.GetAttribute<NotaryAssisted>();
                if (notaryAssisted is not null)
                {
                    totalNetworkFee -= (notaryAssisted.NKeys + 1) * Policy.GetAttributeFeeV1(engine.SnapshotCache, (byte)notaryAssisted.Type);
                }
            }
            ECPoint[] validators = NEO.GetNextBlockValidators(engine.SnapshotCache, engine.ProtocolSettings.ValidatorsCount);
            UInt160 primary = Contract.CreateSignatureRedeemScript(validators[engine.PersistingBlock.PrimaryIndex]).ToScriptHash();
            await Mint(engine, primary, totalNetworkFee, false);
        }
    }
}
