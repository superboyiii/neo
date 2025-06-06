// Copyright (C) 2015-2025 The Neo Project.
//
// ContractParameterDefinition.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using Neo.Json;
using Neo.VM;
using Neo.VM.Types;
using System;
using System.Runtime.CompilerServices;

namespace Neo.SmartContract.Manifest
{
    /// <summary>
    /// Represents a parameter of an event or method in ABI.
    /// </summary>
    public class ContractParameterDefinition : IInteroperable, IEquatable<ContractParameterDefinition>
    {
        /// <summary>
        /// The name of the parameter.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The type of the parameter. It can be any value of <see cref="ContractParameterType"/> except <see cref="ContractParameterType.Void"/>.
        /// </summary>
        public ContractParameterType Type { get; set; }

        void IInteroperable.FromStackItem(StackItem stackItem)
        {
            Struct @struct = (Struct)stackItem;
            Name = @struct[0].GetString();
            Type = (ContractParameterType)(byte)@struct[1].GetInteger();
        }

        public StackItem ToStackItem(IReferenceCounter referenceCounter)
        {
            return new Struct(referenceCounter) { Name, (byte)Type };
        }

        /// <summary>
        /// Converts the parameter from a JSON object.
        /// </summary>
        /// <param name="json">The parameter represented by a JSON object.</param>
        /// <returns>The converted parameter.</returns>
        public static ContractParameterDefinition FromJson(JObject json)
        {
            ContractParameterDefinition parameter = new()
            {
                Name = json["name"].GetString(),
                Type = Enum.Parse<ContractParameterType>(json["type"].GetString())
            };
            if (string.IsNullOrEmpty(parameter.Name))
                throw new FormatException();
            if (!Enum.IsDefined(typeof(ContractParameterType), parameter.Type) || parameter.Type == ContractParameterType.Void)
                throw new FormatException();
            return parameter;
        }

        /// <summary>
        /// Converts the parameter to a JSON object.
        /// </summary>
        /// <returns>The parameter represented by a JSON object.</returns>
        public JObject ToJson()
        {
            var json = new JObject();
            json["name"] = Name;
            json["type"] = Type.ToString();
            return json;
        }

        public bool Equals(ContractParameterDefinition other)
        {
            if (other == null) return false;
            if (ReferenceEquals(this, other)) return true;

            return Name == other.Name && Type == other.Type;
        }

        public override bool Equals(object other)
        {
            if (other is not ContractParameterDefinition parm)
                return false;

            return Equals(parm);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Name, Type);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator ==(ContractParameterDefinition left, ContractParameterDefinition right)
        {
            if (left is null || right is null)
                return Equals(left, right);

            return left.Equals(right);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator !=(ContractParameterDefinition left, ContractParameterDefinition right)
        {
            if (left is null || right is null)
                return !Equals(left, right);

            return !left.Equals(right);
        }
    }
}
