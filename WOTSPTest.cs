/* 
 * Copyright (c) 2019 Asterdite Developers
 * Licensed under The MIT License, read the LICENSE file
 * https://opensource.org/licenses/mit-license.php
 */
using System;
using System.Diagnostics;
using System.Text;
using Asterdite.Secure;

namespace WOTSPTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch duration;
            // Initialize wotsp parameters
            WOTSP.WotsParams wParams = WOTSP.InitParams(32, 256);

            // Generate random parameters
            Random rnd = new Random();
            byte[] keySeed = new byte[wParams.n];
            rnd.NextBytes(keySeed);
            byte[] bitmaskSeed = new byte[wParams.n];
            rnd.NextBytes(bitmaskSeed);
            // Message to sign
            byte[] message = Encoding.ASCII.GetBytes("Hello world!");

            // Sign the message
            WOTSP.KeyGen(wParams, out byte[] privateKey, out byte[] publicKey, keySeed, bitmaskSeed);
            byte[] signature = WOTSP.Sign(wParams, message, privateKey, bitmaskSeed);
            duration = Stopwatch.StartNew();
            bool result = WOTSP.Verify(wParams, publicKey, signature, message, bitmaskSeed);

            // Write info
            Console.WriteLine("Duration: " + duration.ElapsedMilliseconds.ToString() + " ms");
            Console.WriteLine("Signature Size: " + signature.Length.ToString() + " bytes");

            // Write the result
            if (result)
            {
                Console.WriteLine("Result: PASSED");
            }
            else
            {
                Console.WriteLine("Result: Failed");
            }

            // Wait for any key
            Console.WriteLine("Press any key to exit..");
            Console.ReadLine();
        }
    }
}
