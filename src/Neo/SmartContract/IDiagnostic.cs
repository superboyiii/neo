// Copyright (C) 2015-2025 The Neo Project.
//
// IDiagnostic.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Neo.VM;

namespace Neo.SmartContract
{
    public interface IDiagnostic
    {
        void Initialized(ApplicationEngine engine);
        void Disposed();
        void ContextLoaded(ExecutionContext context);
        void ContextUnloaded(ExecutionContext context);
        void PreExecuteInstruction(Instruction instruction);
        void PostExecuteInstruction(Instruction instruction);
    }
}
