// Copyright (C) 2015-2025 The Neo Project.
//
// JBoolean.cs file belongs to the neo project and is free
// software distributed under the MIT software license, see the
// accompanying file LICENSE in the main directory of the
// repository or http://www.opensource.org/licenses/mit-license.php
// for more details.
//
// Redistribution and use in source and binary forms with or without
// modifications are permitted.

using System.Text.Json;

namespace Neo.Json
{
    /// <summary>
    /// Represents a JSON boolean value.
    /// </summary>
    public class JBoolean : JToken
    {
        /// <summary>
        /// Gets the value of the JSON token.
        /// </summary>
        public bool Value { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="JBoolean"/> class with the specified value.
        /// </summary>
        /// <param name="value">The value of the JSON token.</param>
        public JBoolean(bool value = false)
        {
            Value = value;
        }

        public override bool AsBoolean()
        {
            return Value;
        }

        /// <summary>
        /// Converts the current JSON token to a floating point number.
        /// </summary>
        /// <returns>The number 1 if value is <see langword="true"/>; otherwise, 0.</returns>
        public override double AsNumber()
        {
            return Value ? 1 : 0;
        }

        public override string AsString()
        {
            return Value.ToString().ToLowerInvariant();
        }

        public override bool GetBoolean() => Value;

        public override string ToString()
        {
            return AsString();
        }

        internal override void Write(Utf8JsonWriter writer)
        {
            writer.WriteBooleanValue(Value);
        }

        public override JToken Clone()
        {
            return this;
        }

        public static implicit operator JBoolean(bool value)
        {
            return new JBoolean(value);
        }

        public static bool operator ==(JBoolean left, JBoolean right)
        {
            return left.Value.Equals(right.Value);
        }

        public static bool operator !=(JBoolean left, JBoolean right)
        {
            return !left.Value.Equals(right.Value);
        }

        public override bool Equals(object? obj)
        {
            if (ReferenceEquals(this, obj))
            {
                return true;
            }
            if (obj is JBoolean other)
            {
                return Value.Equals(other.Value);
            }
            return false;
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }
    }
}
