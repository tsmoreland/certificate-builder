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

using System.Security.Cryptography.X509Certificates;

namespace TSMoreland.Certificates;

/// <summary>
/// Set of 3 certificates which make up the signature chainf or <see cref="Certificate"/>
/// </summary>
/// <param name="Root">The root certificate</param>
/// <param name="Timestamping">A timestamping certificate signed by <paramref name="Root"/></param>
/// <param name="Certificate">A certificate signed by <paramref name="Timestamping"/></param>
public sealed record class CertificateSet(
    X509Certificate2 Root,
    X509Certificate2 Timestamping,
    X509Certificate2 Certificate)
{

    /// <summary>
    /// The root certificate, the signing cert for <see cref="Timestamping"/>
    /// and by extension <see cref="Certificate"/>
    /// </summary>
    public X509Certificate2 Root { get; init; } = Root;

    /// <summary>
    /// A timestamping certificate signed by <see cref="Root"/>
    /// </summary>
    public X509Certificate2 Timestamping { get; init; } = Timestamping;

    /// <summary>
    /// A certificate signed by <see cref="Timestamping"/> and by
    /// extension <see cref="Root"/>
    /// </summary>
    public X509Certificate2 Certificate { get; init; } = Certificate;

}
