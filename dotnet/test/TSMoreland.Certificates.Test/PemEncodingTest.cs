//
// Copyright © 2022 Terry Moreland
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System.Security.Cryptography;

#if !NET6_0_OR_GREATER
namespace TSMoreland.Certificates.Test;

public sealed class PemEncodingTest
{
    [TestCase(24)]
    [TestCase(48)]
    public void Write_ReturnsSingleBase64EncodedLineWrapedInBeginAndEnd_WhenDataSmallerThan48Bytes(int size)
    {
        byte[] data = GetRandomBytes(size);
        string encoded = new (PemEncoding.Write("CERTIFICATE", data));

        string[] lines = encoded.Split('\n');

        Assert.That(lines.Length, Is.EqualTo(4));
        StringAssert.Contains("BEGIN CERTIFICATE", lines[0]);
        Assert.That(lines[1].Length, Is.LessThanOrEqualTo(64)); // 48 * 4/3 caused by base64 encoding
        StringAssert.Contains("END CERTIFICATE", lines[2]);

    }

    private static byte[] GetRandomBytes(int size)
    {
        byte[] data = new byte[size];
        using RNGCryptoServiceProvider generator = new();
        generator.GetBytes(data);
        return data;
    }
}
#endif
