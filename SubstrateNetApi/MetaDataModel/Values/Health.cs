﻿using Newtonsoft.Json;

namespace SubstrateNetApi.MetaDataModel.Values
{
    public class Health
    {
        public bool isSyncing { get; set; }
        public int peers { get; set; }
        public bool shouldHavePeers { get; set; }
        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
