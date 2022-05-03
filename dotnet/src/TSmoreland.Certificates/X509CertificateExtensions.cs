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
using System.Security.Cryptography.X509Certificates;

namespace TSMoreland.Certificates;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/> or <see cref="X509Certificate"/>
/// </summary>
public static class X509CertificateExtensions
{
    /// <summary>
    /// Export <paramref name="certificate"/> to <paramref name="path"/> folder
    /// with filename of <paramref name="filenameWithoutExtension"/> and pfx extension
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="path">folder to export to</param>
    /// <param name="filenameWithoutExtension">filename without extension</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>the absolute path to the exported PFX file</returns>
    /// <exception cref="ArgumentException">
    /// if <paramref name="path"/> is empty, does not exist or contains ..
    /// or if filename is empty, or contains ..
    /// </exception>
    public static string ExportToPfx(this X509Certificate certificate, string path, string filenameWithoutExtension, string? password)
    {
        ThrowIfArgumentsAreInvalid(path, filenameWithoutExtension);
        string fullpath = Path.Combine(path, $"{filenameWithoutExtension}.pfx");
        File.WriteAllBytes(fullpath,
            password is { Length: > 0 }
                ? certificate.Export(X509ContentType.Pfx, password)
                : certificate.Export(X509ContentType.Pfx));

        return fullpath;
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Exports the file to PEM
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="path">folder to export to</param>
    /// <param name="filenameWithoutExtension">filename without extension</param>
    /// <returns></returns>
    /// <exception cref="ArgumentException">
    /// if <paramref name="path"/> is empty, does not exist or contains ..
    /// or if filename is empty, or contains ..
    /// </exception>
    /// <exception cref="CryptographicException">
    /// if the algorithm of <paramref name="certificate"/> is unknown
    /// </exception>
    public static (string certificatePath, string keyPath) ExportToPem(this X509Certificate2 certificate, string path, string filenameWithoutExtension)
    {
        ThrowIfArgumentsAreInvalid(path, filenameWithoutExtension);

        byte[] rawData = certificate.GetRawCertData();
        string pemCertificate = new (PemEncoding.Write("CERTIFICATE", rawData));

        string key;
        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetECDsaPrivateKey() is {} ecdsaKey)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", ecdsaKey.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetDSAPrivateKey() is {} dsaKey)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", dsaKey.ExportPkcs8PrivateKey()));
        }
        else
        {
            throw new CryptographicException("Unknown algorithm");
        }

        string pemFullpath = Path.Combine(path, $"{filenameWithoutExtension}.pem");
        string keyFullpath = Path.Combine(path, $"{filenameWithoutExtension}.key");
        File.WriteAllText(pemFullpath, pemCertificate);
        File.WriteAllText(keyFullpath, key);

        return (pemFullpath, keyFullpath);
    }
#endif
    /// <summary>
    /// Export <paramref name="certificate"/> to certificate file
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="path">folder to export to</param>
    /// <param name="filenameWithoutExtension">filename without extension</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>the absolute path to the exported certificate</returns>
    /// <exception cref="ArgumentException">
    /// if <paramref name="path"/> is empty, does not exist or contains ..
    /// or if filename is empty, or contains ..
    /// </exception>
    public static string Export(this X509Certificate certificate, string path, string filenameWithoutExtension, string? password)
    {
        ThrowIfArgumentsAreInvalid(path, filenameWithoutExtension);
        string fullpath = Path.Combine(path, $"{filenameWithoutExtension}.cer");
        File.WriteAllBytes(fullpath,
            password is { Length: > 0 }
                ? certificate.Export(X509ContentType.Cert, password)
                : certificate.Export(X509ContentType.Cert));

        return fullpath;
    }

    private static void ThrowIfArgumentsAreInvalid(string path, string filenameWithoutExtension)
    {
        if (path is not { Length: > 0 } || !Directory.Exists(path) || path.Contains(".."))
        {
            throw new ArgumentException($"{path} does not exist.", nameof(path)); 
        }

        if (filenameWithoutExtension is not {Length: >0} || filenameWithoutExtension.Contains(".."))
        {
            throw new ArgumentException($"invalid filename.", nameof(filenameWithoutExtension)); 
        }
    }
}
