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
using System.Text;

namespace TSMoreland.Certificates.Extensions;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/> or <see cref="X509Certificate"/>
/// </summary>
public static class X509CertificateExtensions
{
    internal static class PemLabels
    {
        internal const string Pkcs8PrivateKey = "PRIVATE KEY";
        internal const string EncryptedPkcs8PrivateKey = "ENCRYPTED PRIVATE KEY";
        internal const string SpkiPublicKey = "PUBLIC KEY";
        internal const string RsaPublicKey = "RSA PUBLIC KEY";
        internal const string RsaPrivateKey = "RSA PRIVATE KEY";
        internal const string EcPrivateKey = "EC PRIVATE KEY";
        internal const string X509Certificate = "CERTIFICATE";
        internal const string Pkcs7Certificate = "PKCS7";
    }

    /// <summary>
    /// convert <paramref name="certificate"/> to PFX format stored in a byte array
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>A byte array containing the PFX data</returns>
    public static byte[] ToPfx(this X509Certificate certificate, string? password)
    {
        return password is { Length: > 0 }
            ? certificate.Export(X509ContentType.Pfx, password)
            : certificate.Export(X509ContentType.Pfx);
    }

#if NET7_0_OR_GREATER
    /// <summary>
    /// Exports the file to PEM
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>a pair of strings representing the PEM encoded certifcate and key</returns>
    /// <exception cref="CryptographicException">
    /// if the algorithm of <paramref name="certificate"/> is unknown
    /// </exception>
    public static (string certificate, string key) ToPemEncodedCertificateKeyPair(this X509Certificate2 certificate, string? password)
    {
        byte[] rawData = certificate.GetRawCertData();
        string pemCertificate = certificate.ExportCertificatePem();


        IReadOnlyList<(Func<object?>, string?)> producers = new List<(Func<object?>, string?)>
        {
            (certificate.GetRSAPrivateKey, password),
            (certificate.GetDSAPrivateKey, password),
            (certificate.GetECDsaPrivateKey, password),
            (certificate.GetECDiffieHellmanPrivateKey, password),
        };


        string? privateKey = producers
            .Select(p => (p.Item1.Invoke(), p.Item2))
            .Where(p => p.Item1 is not null)
            .Select(p => GetPrivateKeyBytesOrThrow(p.Item1, p.Item2))
            .FirstOrDefault();

        if (privateKey is null)
        {
            throw new CryptographicException("Private key not found");
        }

        return (pemCertificate, privateKey);

        static string GetPrivateKeyBytesOrThrow(object? privateKeyObject, string? password)
        {
            PbeParameters parameters = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100);
            return privateKeyObject switch
            {
                RSA rsa when password is not null => rsa.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),
                DSA dsa when password is not null => dsa.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),
                ECDsa ecdsa when password is not null => ecdsa.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),
                ECDiffieHellman ecDiffieHellman when password is not null => ecDiffieHellman.ExportEncryptedPkcs8PrivateKeyPem(password, parameters),

                RSA rsa when password is null => rsa.ExportPkcs8PrivateKeyPem(),
                DSA dsa when password is null => dsa.ExportPkcs8PrivateKeyPem(),
                ECDsa ecdsa when password is null => ecdsa.ExportPkcs8PrivateKeyPem(),
                ECDiffieHellman ecDiffieHellman when password is null => ecDiffieHellman.ExportPkcs8PrivateKeyPem(),
                _ => throw  new NotSupportedException(),
            };
        }
    }
#elif NET6_0
    /// <summary>
    /// Exports the file to PEM
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>a pair of strings representing the PEM encoded certifcate and key</returns>
    /// <exception cref="CryptographicException">
    /// if the algorithm of <paramref name="certificate"/> is unknown
    /// </exception>
    public static (string certificate, string key) ToPemEncodedCertificateKeyPair(this X509Certificate2 certificate, string? password)
    {
        byte[] rawData = certificate.GetRawCertData();
        string pemCertificate = new(PemEncoding.Write(PemLabels.X509Certificate, rawData));

        IReadOnlyList<(Func<object?>, string?)> producers = new List<(Func<object?>, string?)>
        {
            (certificate.GetRSAPrivateKey, password),
            (certificate.GetDSAPrivateKey, password),
            (certificate.GetECDsaPrivateKey, password),
            (certificate.GetECDiffieHellmanPrivateKey, password),
        };

        byte[]? privateKey = producers
            .Select(p => (p.Item1.Invoke(), p.Item2))
            .Where(p => p.Item1 is not null)
            .Select(p => GetPrivateKeyBytesOrThrow(p.Item1, p.Item2))
            .FirstOrDefault();

        if (privateKey is null)
        {
            throw new CryptographicException("Private key not found");
        }

        string keyLabel = password is not null
            ? PemLabels.EncryptedPkcs8PrivateKey
            : PemLabels.Pkcs8PrivateKey;
        string key = new (PemEncoding.Write(keyLabel, privateKey));

        return (pemCertificate, key);

        static byte[] GetPrivateKeyBytesOrThrow(object? privateKeyObject, string? password)
        {
            return privateKeyObject switch
            {
                RSA rsa when password is not null =>  rsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                DSA dsa when password is not null => dsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                ECDsa ecdsa when password is not null => ecdsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                ECDiffieHellman ecDiffieHellman when password is not null => ecDiffieHellman.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),

                RSA rsa when password is null =>  rsa.ExportPkcs8PrivateKey(),
                DSA dsa when password is null => dsa.ExportPkcs8PrivateKey(),
                ECDsa ecdsa when password is null => ecdsa.ExportPkcs8PrivateKey(),
                ECDiffieHellman ecDiffieHellman when password is null => ecDiffieHellman.ExportPkcs8PrivateKey(),
                _ => throw  new NotSupportedException(),
            };
        }
    }
#else

    /// <summary>
    /// Exports the file to PEM
    /// </summary>
    /// <param name="certificate">the certificate to export</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>a pair of strings representing the PEM encoded certifcate and key</returns>
    /// <exception cref="CryptographicException">
    /// if the algorithm of <paramref name="certificate"/> is unknown
    /// </exception>
    public static (string certificate, string key) ToPemEncodedCertificateKeyPair(this X509Certificate2 certificate, string? password)
    {
        byte[] rawData = certificate.GetRawCertData();
        string pemCertificate = new(PemEncoding.Write("CERTIFICATE", rawData));
        string key;

        string keyLabel = password is not null
            ? PemLabels.EncryptedPkcs8PrivateKey
            : PemLabels.Pkcs8PrivateKey;

        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
        }

        /*
        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
            key = new string(PemEncoding.Write(keyLabel, rsa.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetECDsaPrivateKey() is { } ecdsaKey)
        {
            key = new string(PemEncoding.Write(keyLabel, ecdsaKey.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetDSAPrivateKey() is { } dsaKey)
        {
            key = new string(PemEncoding.Write(keyLabel, dsaKey.ExportPkcs8PrivateKey()));
        }
        else
        {
            throw new CryptographicException("Unknown algorithm");
        }

        return (pemCertificate, key);
        */
        return (string.Empty, string.Empty);
    }
#endif


    /// <summary>
    /// Convert <paramref name="certificate"/> to byte array in <see cref="X509ContentType.Cert"/> format
    /// </summary>
    /// <param name="certificate">the certificate to convert</param>
    /// <param name="password">optional password, ignored if <see langword="null"/> or empty.</param>
    /// <returns>byte array containing the converted certificate</returns>
    public static byte[] ToByteArray(this X509Certificate certificate, string? password)
    {
        return password is { Length: > 0 }
            ? certificate.Export(X509ContentType.Cert, password)
            : certificate.Export(X509ContentType.Cert);
    }

    private static void ThrowIfArgumentsAreInvalid(string path, string filenameWithoutExtension)
    {
        if (path is not { Length: > 0 } || !Directory.Exists(path) || path.Contains(".."))
        {
            throw new ArgumentException($"{path} does not exist.", nameof(path));
        }

        if (filenameWithoutExtension is not { Length: > 0 } || filenameWithoutExtension.Contains(".."))
        {
            throw new ArgumentException($"invalid filename.", nameof(filenameWithoutExtension));
        }
    }
}
