﻿namespace SubstrateNetApi.MetaDataModel
{
    public class Storage
    {
        public enum Type
        {
            Plain, Map, DoubleMap
        }

        public enum Modifier
        {
            Optional,
            Default
        }

        public enum Hasher
        {
            None = -1,
            Blake2_128,
            Blake2_256,
            Blake2_128Concat,
            Twox128,
            Twox256,
            Twox64Concat,
            Identity
        }

        public string Prefix { get; internal set; }
        public Item[] Items { get; internal set; }

    }
}