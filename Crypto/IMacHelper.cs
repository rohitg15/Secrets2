using System;

namespace Crypto
{
    public interface IMacHelper
    {
        void Init(MacAlgorithm algorithm, byte[] key);
        byte[] GetMac(byte[] message);

        bool VerifyMac(byte[] mac, byte[] message);
    }
}