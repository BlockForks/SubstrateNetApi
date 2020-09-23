using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Security.Cryptography;
using System.Text;
using Schnorrkel.Merlin;
using Schnorrkel.Scalars;

namespace Schnorrkel.Keys
{

    public class PrivateKey
    {
        private byte[] _seed;

        private byte[] _key;

        private byte[] _nonce;

        private byte[] _h;

        public byte[] Key => _key;

        public byte[] Nonce => _nonce;

        public PrivateKey(byte[] seed)
        {
            _seed = seed;
            ExpandED25519(seed);
        }

        private void ExpandED25519(byte[] seed)
        {
            SHA512 shaM = new SHA512Managed();
            _h = shaM.ComputeHash(seed);
            _h[0] &= unchecked((byte)248);
            _h[31] &= 63;
            _h[31] |= 64;
            _key = _h.AsMemory().Slice(0, 32).ToArray();
            Scalar.DivideScalarBytesByCofactor(ref _key);
            _nonce = _h.AsMemory().Slice(32, 32).ToArray();
        }

        private void ExpandUniform(byte[] seed)
        {
            Transcript t = new Transcript(Encoding.UTF8.GetBytes("ExpandSecretKeys"));
            t.AppendMessage(Encoding.UTF8.GetBytes("mini"), seed);
            byte[] scalar_bytes = new byte[64];
            t.ChallengeBytes(Encoding.UTF8.GetBytes("sk"), ref scalar_bytes);
            Scalar scalar = Scalar.FromBytesModOrderWide(scalar_bytes);
            _key = scalar.GetBytes(); // .ScalarBytes; // GetBytes();
            _nonce = new byte[32];
            t.ChallengeBytes(Encoding.UTF8.GetBytes("no"), ref _nonce);
        }
    }
}