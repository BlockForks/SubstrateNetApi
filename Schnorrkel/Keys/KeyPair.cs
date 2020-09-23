using System;
using System.Collections.Generic;
using System.Text;
using Schnorrkel.Ristretto;
using Schnorrkel.Scalars;

namespace Schnorrkel.Keys
{
    public class KeyPair
    {
        private readonly PublicKey _publicKey;

        private readonly PrivateKey _privateKey;

		public PublicKey PublicKey => _publicKey;

		public PrivateKey PrivateKey => _privateKey;

		public KeyPair(PublicKey publicKey, PrivateKey privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

		public static KeyPair fromSecretSeed(byte[] seed)
		{
			PrivateKey privateKey = new PrivateKey(seed);

			var scalar = new Scalar { ScalarBytes = seed.AsMemory().Slice(0, 32).ToArray() };

			var ristrettoBasepointTable = new RistrettoBasepointTable();
			var ristrettoPoint = ristrettoBasepointTable.Mul(scalar);

			PublicKey publicKey = new PublicKey(ristrettoPoint);

			return new KeyPair(publicKey, privateKey);
		}

		public static KeyPair generateKeyPair()
		{
			Random random = new Random();
			byte[] seed = new byte[32];
			random.NextBytes(seed);
			return fromSecretSeed(seed);
		}

	}
}
