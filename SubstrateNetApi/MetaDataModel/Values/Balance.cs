﻿using System;
using System.Numerics;

namespace SubstrateNetApi.MetaDataModel.Values
{
    public class Balance : IEncodable
    {
        public CompactInteger Value { get; }

        public Balance(string str) : this(Utils.HexToByteArray(str).AsMemory())
        {
        }

        internal Balance(Memory<byte> memory)
        {
            Value = new BigInteger(memory.ToArray());
        }

        public Balance(BigInteger value)
        {
            Value = value;
        }

        public byte[] Encode()
        {
            return Value.Encode();
        }
    }
}
