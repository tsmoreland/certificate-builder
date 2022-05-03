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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TSMoreland.Certificates;

/// <summary>
/// Data Storage object for certificate settings used to generate a <see cref="X509Certificate2"/>
/// </summary>
public sealed record class ExtendedSignedCertificateSettings(
    string SubjectName,
    int KeySizeInBits,
    DateTime? NotBefore,
    DateTime? NotAfter,
    IEnumerable<string> AlternateNames,
    IEnumerable<Oid> AdditionalKeyUsages,
    byte[] SerialNumber,
    X509KeyUsageFlags UsageFlags,
    bool Critical = false)
{

    /// <summary>
    /// Insatantiates a new instance of the <see cref="ExtendedSignedCertificateSettings"/> class.
    /// </summary>
    public ExtendedSignedCertificateSettings(
        string subjectName,
        int keySizeInBits,
        DateTime? notBefore,
        DateTime? notAfter,
        IEnumerable<string> alternateNames,
        IEnumerable<Oid> additionalKeyUsages,
        byte[] serialNumber)
        : this(subjectName, keySizeInBits, notBefore, notAfter, alternateNames, additionalKeyUsages, serialNumber,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
            false)
    {

    }

}
