/* 
 * Copyright (c) 2019 Asterdite Developers
 * Licensed under The MIT License, read the LICENSE file
 * https://opensource.org/licenses/mit-license.php
 */
using System;
using System.Security.Cryptography;

namespace Asterdite.Secure
{
    /* 
     * xmss-reference code
     * Andreas Hülsing, Joost Rijneveld 
     * CC0 1.0 Universal Public Domain
     */
    public class WOTSP
    {
        public const int SHA2 = 0;
        const int HASH_PADDING_F = 0x0;
        const int HASH_PADDING_PRF = 0x1;
        private static int[] Address = new int[8];

        public struct WotsParams
        {
            public int func;
            public int n;
            public int w;
            public int logW;
            public int length1;
            public int length2;
            public int length;
            public int keyLength;
        };

        public static WotsParams InitParams(int n, int w)
        {
            WotsParams wParams = new WotsParams();

            if (n == 32 || n == 64)
            {
                if ((w & (w - 1)) == 0)
                {
                    wParams.n = n;
                    wParams.w = w;
                    wParams.logW = (int)Math.Log(wParams.w, 2);

                    if (8 % wParams.logW == 0)
                    {
                        wParams.length1 = 8 * wParams.n / wParams.logW;
                        wParams.length2 = (int)(Math.Floor(Math.Log(wParams.length1 * (wParams.w - 1), 2) / wParams.logW) + 1);
                        wParams.length = wParams.length1 + wParams.length2;
                        wParams.keyLength = wParams.n * wParams.length;
                    }
                }
            }

            return wParams;
        }

        static byte[] LongToBytes(long input, int outputLength)
        {
            byte[] output = new byte[outputLength];

            for (int i = outputLength - 1; i >= 0; i--)
            {
                output[i] = (byte)(input & 0xff);
                input = input >> 8;
            }

            return output;
        }

        static bool CoreHash(WotsParams wParams, out byte[] output, byte[] input, int inputLenth)
        {
            output = null;

            if (wParams.n == 32 && wParams.func == SHA2)
            {
                SHA256Managed sha256 = new SHA256Managed();
                output = sha256.ComputeHash(input, 0, inputLenth);
            }
            else
            if (wParams.n == 64 && wParams.func == SHA2)
            {
                SHA512Managed sha512 = new SHA512Managed();
                output = sha512.ComputeHash(input, 0, inputLenth);
            }
            else
            {
                return false;
            }

            return true;
        }

        static byte[] AddressToBytes(int[] address)
        {
            byte[] bytes = new byte[32];

            for (int i = 0; i < 8; i++)
            {
                byte[] addressBytes = LongToBytes(address[i], 4);
                addressBytes.CopyTo(bytes, i * 4);
            }

            return bytes;
        }

        static void SetKeyMaskAddress(int[] address, int keyAndMask)
        {
            address[7] = keyAndMask;
        }

        static void SetHashAddress(int[] address, int hash)
        {
            address[6] = hash;
        }

        static void SetChainAddress(int[] address, int chain)
        {
            address[5] = chain;
        }

        static bool PRF(WotsParams wParams, out byte[] output, byte[] input, byte[] key)
        {
            byte[] buffer = new byte[2 * wParams.n + 32];
            byte[] padding = LongToBytes(HASH_PADDING_PRF, wParams.n);
            padding.CopyTo(buffer, 0);

            Array.Copy(key, 0, buffer, wParams.n, wParams.n);
            Array.Copy(input, 0, buffer, 2 * wParams.n, 32);

            return CoreHash(wParams, out output, buffer, 2 * wParams.n + 32);
        }

        static bool HashF(WotsParams wParams, out byte[] output, byte[] input, byte[] bitmaskSeed)
        {
            byte[] buffer = new byte[3 * wParams.n];
            byte[] addressBytes = new byte[32];

            byte[] padding = LongToBytes(HASH_PADDING_F, wParams.n);
            padding.CopyTo(buffer, 0);

            SetKeyMaskAddress(Address, 0);
            addressBytes = AddressToBytes(Address);
            PRF(wParams, out byte[] pseudo, addressBytes, bitmaskSeed);
            pseudo.CopyTo(buffer, wParams.n);

            SetKeyMaskAddress(Address, 1);
            addressBytes = AddressToBytes(Address);
            PRF(wParams, out byte[] bitmask, addressBytes, bitmaskSeed);

            for (int i = 0; i < wParams.n; i++)
            {
                buffer[2 * wParams.n + i] = (byte)(input[i] ^ bitmask[i]);
            }

            return CoreHash(wParams, out output, buffer, 3 * wParams.n);
        }

        static byte[] ExpandSeed(WotsParams wParams, byte[] inSeed)
        {
            byte[] outSeed = new byte[wParams.length * wParams.n];
            byte[] counter = new byte[32];

            for (int i = 0; i < wParams.length; i++)
            {
                counter = LongToBytes(i, 32);
                PRF(wParams, out byte[] pseudo, counter, inSeed);
                pseudo.CopyTo(outSeed, i * wParams.n);
            }

            return outSeed;
        }

        static byte[] GenChain(WotsParams wParams, byte[] input, int start, int steps, byte[] bitmaskSeed)
        {
            byte[] output = new byte[wParams.n];

            Array.Copy(input, output, wParams.n);

            for (int i = start; i < (start + steps) && i < wParams.w; i++)
            {
                SetHashAddress(Address, i);
                HashF(wParams, out output, output, bitmaskSeed);
            }

            return output;
        }

        static int[] BaseW(WotsParams wParams, byte[] input, int outputLength)
        {
            int[] output = new int[outputLength];
            int i = 0;
            int j = 0;
            byte total = 0;
            int bits = 0;

            for (int consumed = 0; consumed < outputLength; consumed++)
            {
                if (bits == 0)
                {
                    if (input.Length > i)
                    {
                        total = input[i];
                    }
                    else
                    {
                        total = 0;
                    }
                    i++;
                    bits += 8;
                }
                bits -= wParams.logW;
                output[j] = (total >> bits) & (wParams.w - 1);
                j++;
            }

            return output;
        }

        static int[] CheckSum(WotsParams wParams, int[] messageBaseW)
        {
            int[] csumBaseW = new int[wParams.length2];
            int csum = 0;
            byte[] csumBytes = new byte[(wParams.length2 * wParams.logW + 7) / 8];

            for (int i = 0; i < wParams.length1; i++)
            {
                csum += wParams.w - 1 - messageBaseW[i];
            }

            csum = csum << (8 - ((wParams.length2 * wParams.logW) % 8));
            csumBytes = LongToBytes(csum, csumBytes.Length);
            csumBaseW = BaseW(wParams, csumBytes, wParams.length2);

            return csumBaseW;
        }

        static int[] ChainLengths(WotsParams wParams, byte[] message)
        {
            int[] lengths = new int[wParams.length];

            int[] messageBaseW = BaseW(wParams, message, wParams.length1);
            messageBaseW.CopyTo(lengths, 0);
            int[] csumBaseW = CheckSum(wParams, messageBaseW);
            csumBaseW.CopyTo(lengths, wParams.length1);

            return lengths;
        }
 
        public static void KeyGen(WotsParams wParams, out byte[] privateKey, out byte[] publicKey, byte[] keySeed, byte[] bitmaskSeed)
        {
            byte[] buffer = new byte[wParams.n];

            privateKey = ExpandSeed(wParams, keySeed);
            publicKey = new byte[wParams.keyLength];

            for (int i = 0; i < wParams.length; i++)
            {
                SetChainAddress(Address, i);
                Array.Copy(privateKey, i * wParams.n, buffer, 0, buffer.Length);
                buffer = GenChain(wParams, buffer, 0, wParams.w - 1, bitmaskSeed);
                buffer.CopyTo(publicKey, i * wParams.n);
            }
        }

        public static byte[] Sign(WotsParams wParams, byte[] message, byte[] privateKey, byte[] bitmaskSeed)
        {
            byte[] signature = new byte[wParams.keyLength];
            byte[] buffer = new byte[wParams.n];
            int[] lengths = ChainLengths(wParams, message);

            for (int i = 0; i < wParams.length; i++)
            {
                SetChainAddress(Address, i);
                Array.Copy(privateKey, i * wParams.n, buffer, 0, wParams.n);
                buffer = GenChain(wParams, buffer, 0, lengths[i], bitmaskSeed);
                buffer.CopyTo(signature, i * wParams.n);
            }

            return signature;
        }

        public static bool Verify(WotsParams wParams, byte[] publicKey, byte[] signature, byte[] message, byte[] bitmaskSeed)
        {
            byte[] buffer = new byte[wParams.n];
            int[] lengths = ChainLengths(wParams, message);

            for (int i = 0; i < wParams.length; i++)
            {
                SetChainAddress(Address, i);
                Array.Copy(signature, i * wParams.n, buffer, 0, buffer.Length);
                buffer = GenChain(wParams, buffer, lengths[i], wParams.w - 1 - lengths[i], bitmaskSeed);

                for (int j = 0; j < buffer.Length; j++)
                {
                    if (buffer[j] != publicKey[j + i * wParams.n])
                    {
                        return false;
                    }
                }
            }

            return true;
        }

    }
}

