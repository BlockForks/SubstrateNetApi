﻿using Newtonsoft.Json;
using System;

namespace SubstrateNetApi.MetaDataModel.Values
{
    public class AccountId : IEncodable
    {
        public string Address { get; }

        public byte[] PublicKey { get; }

        public static AccountId CreateFromAddress(string address) => new AccountId(Utils.GetPublicKeyFrom(address));

        public AccountId(byte[] publicKey)
        {
            Address = Utils.GetAddressFrom(publicKey);
            PublicKey = publicKey;
        }

        public AccountId(string str) : this(Utils.HexToByteArray(str).AsMemory())
        {
        }

        internal AccountId(Memory<byte> memory)
        {
            PublicKey = memory.ToArray();
            Address = Utils.GetAddressFrom(PublicKey);
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }

        public byte[] Encode()
        {
            return PublicKey;
        }
    }
}