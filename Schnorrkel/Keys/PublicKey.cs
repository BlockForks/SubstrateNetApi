using System;
using Schnorrkel.Ristretto;

namespace Schnorrkel
{
    public class PublicKey
    {
        private RistrettoPoint _ristrettoPoint;

        private CompressedRistretto _compressedRistretto;

        public byte[] Key { get; }

        public PublicKey(byte[] keyBytes)
        {
            Key = keyBytes;
        }

        public PublicKey(RistrettoPoint ristrettoPoint)
        {
            _ristrettoPoint = ristrettoPoint;
            _compressedRistretto = ristrettoPoint.Compress();

            Key = _compressedRistretto.GetBytes();
        }

        internal EdwardsPoint GetEdwardsPoint()
        {
            return EdwardsPoint.Decompress(Key);
        }
    }
}
