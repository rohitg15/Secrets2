using Xunit;
using System;
using System.Security.Cryptography;
using Crypto;
using Utils;

namespace Test
{
    public class MacHelperTest
    {
        public MacAlgorithm hmacSha256 { get; set; }

        public MacAlgorithm hmacSha512 { get; set; }

        public byte[] key256 { get; set; }
        public byte[] key512 { get; set; }

        public RandomNumberGenerator csprng { get; set; }

        public MacHelperTest()
        {
            this.hmacSha256 = new MacAlgorithm(MacAlgorithmType.HMAC_SHA256);
            this.hmacSha512 = new MacAlgorithm(MacAlgorithmType.HMAC_SHA512);
            this.csprng = RandomNumberGenerator.Create();
            this.key256 = new byte[32];
            this.key512 = new byte[64];
            this.csprng.GetBytes(this.key256, 0, this.key256.Length);
            this.csprng.GetBytes(this.key512, 0, this.key512.Length);
        }

        [Fact]
        public void TestInitNullAlgorithm()
        {
            IMacHelper macHelper = new MacHelper();
            Assert.Throws<ArgumentNullException>(
                () =>
                    macHelper.Init(null, this.key256)
            );
        }

        [Fact]
        public void TestInitNullKey()
        {
            IMacHelper macHelper = new MacHelper();
            Assert.Throws<ArgumentNullException>(
                () =>
                    macHelper.Init(this.hmacSha256, null)
            );
        }

        [Fact]
        public void TestInitHmacSha256KeySize()
        {
            IMacHelper macHelper = new MacHelper();
            Assert.Throws<CryptographicException>(
                () =>
                    macHelper.Init(this.hmacSha256, this.key512)
            );
        }


        [Fact]
        public void TestGetMacNullMessage()
        {
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            Assert.Throws<ArgumentNullException>(
                () =>
                    macHelper.GetMac(null)
            );
        }

        [Fact]
        public void TestGetMacHmacSha256Size()
        {
            // initialize
            IMacHelper macHelper =  new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] message = new byte[28];

            // when
            byte[] mac = macHelper.GetMac(message);

            // then
            Assert.Equal(32, mac.Length);
        }

        [Fact]
        public void TestGetMacHmacSha512Size()
        {
            // initialize
            IMacHelper macHelper =  new MacHelper();
            macHelper.Init(this.hmacSha512, this.key512);
            byte[] message = new byte[28];

            // when
            byte[] mac = macHelper.GetMac(message);

            // then
            Assert.Equal(64, mac.Length);            
        }

        [Fact]
        public void TestGetMacSameMessage()
        {
            // initialize
            IMacHelper macHelper =  new MacHelper();
            macHelper.Init(this.hmacSha512, this.key512);
            byte[] message1 = new byte[28];
            byte[] message2 = new byte[28];

            for(int i = 0; i < 28; ++i)
            {
                message1[i] = (byte)i;
                message2[i] = (byte)i;
            }

            // when
            byte[] mac1 = macHelper.GetMac(message1);
            byte[] mac2 = macHelper.GetMac(message2);

            // then
            Assert.Equal(mac1.Length, mac2.Length);
            Assert.Equal(mac1, mac2);                        
        }

        [Fact]
        public void TestVerifyMacNullMessage()
        {
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] mac = new byte[32];
            Assert.Throws<ArgumentNullException>(
                () =>
                    macHelper.VerifyMac(null, mac)
            );
        }

        [Fact]
        public void TestVerifyMacNullHmac()
        {
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] msg = new byte[32];
            Assert.Throws<ArgumentNullException>(
                () =>
                    macHelper.VerifyMac(msg, null)
            );
        }

        [Fact]
        public void TestVerifyMacInvalidMac()
        {
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] mac = new byte[32];
            byte[] msg = new byte[32];
            Assert.False(macHelper.VerifyMac(msg, mac));
        }

        [Fact]
        public void TestVerifyMacValidMac()
        {
            // initialization
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] msg = new byte[32];
            for(int i = 0; i < msg.Length; ++i)
            {
                msg[i] = (byte)i;
            }

            // when
            byte[] mac = macHelper.GetMac(msg);

            // then
            Assert.True(macHelper.VerifyMac(msg, mac));
        }

        [Fact]
        public void TestVerifyDifferentMacDifferentMsg()
        {
            // initialization
            IMacHelper macHelper = new MacHelper();
            macHelper.Init(this.hmacSha256, this.key256);
            byte[] msg1 = new byte[32];
            byte[] msg2 = new byte[32];
            for(int i = 0; i < msg1.Length; ++i)
            {
                msg1[i] = (byte)i;
                msg2[i] = (byte)i;
            }

            // change 1 byte
            msg2[31] = msg2[30];

            // when
            byte[] mac1 = macHelper.GetMac(msg1);
            byte[] mac2 = macHelper.GetMac(msg2);

            // then
            Assert.NotEqual(mac1, mac2);
        }

        [Fact]
        public void TestVerifyMacValidMacWrongAlgorithm()
        {
            // initialization
            IMacHelper hmac256 = new MacHelper();
            hmac256.Init(this.hmacSha256, this.key256);
            
            IMacHelper hmac512 = new MacHelper();
            hmac512.Init(this.hmacSha512, this.key512);
            
            byte[] msg = new byte[143];
            for(int i = 0; i < msg.Length; ++i)
            {
                msg[i] = (byte)i;
            }

            // when
            byte[] mac256 = hmac256.GetMac(msg);
            byte[] mac512 = hmac512.GetMac(msg);

            // then
            Assert.False(hmac256.VerifyMac(msg, mac512));
            Assert.False(hmac512.VerifyMac(msg, mac256));
        }


    }
}