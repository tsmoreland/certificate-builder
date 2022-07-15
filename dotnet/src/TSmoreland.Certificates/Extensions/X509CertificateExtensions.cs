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

#if NET6_0_OR_GREATER
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

        IReadOnlyList<Func<object?>> producers = new List<Func<object?>>
        {
            certificate.GetRSAPrivateKey,
            certificate.GetDSAPrivateKey,
            certificate.GetECDsaPrivateKey,
            certificate.GetECDiffieHellmanPrivateKey,
        };

        byte[]? privateKey = producers
            .Select(p => p.Invoke())
            .Cast<object?>()
            .Where(p => p is not null)
            .Select(GetPrivateKeyBytesOrThrow)
            .FirstOrDefault();

        if (privateKey is null)
        {
            throw new CryptographicException("Private key not found");
        }

        string key = new (PemEncoding.Write("PRIVATE KEY", privateKey));
        return (pemCertificate, key);

        byte[] GetPrivateKeyBytesOrThrow(object? privateKeyObject)
        {
            return privateKeyObject switch
            {
                RSA rsa => rsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                DSA dsa => dsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                ECDsa ecdsa => ecdsa.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
                ECDiffieHellman ecDiffieHellman => ecDiffieHellman.ExportEncryptedPkcs8PrivateKey(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100)),
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
        /*
        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetECDsaPrivateKey() is { } ecdsaKey)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", ecdsaKey.ExportPkcs8PrivateKey()));
        }
        else if (certificate.GetDSAPrivateKey() is { } dsaKey)
        {
            key = new string(PemEncoding.Write("PRIVATE KEY", dsaKey.ExportPkcs8PrivateKey()));
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

#if NET6_0_OR_GREATER

    /// <summary>
    /// Gets the public key string representation displaying algorithm name and key size in bits or empty
    /// if unable to obtain this information
    /// </summary>
    /// <param name="certificate">the certificate to get public key details of</param>
    /// <returns>
    /// string detailing the algorithm and key size in bits on success; otherwise <see cref="string.Empty"/>
    /// </returns>
    public static string GetPublicKeyTypeOrEmpty(this X509Certificate2 certificate)
    {
        IReadOnlyList<Func<object?>> producers = new List<Func<object?>>()
        {
            certificate.GetDSAPublicKey,
            certificate.GetRSAPublicKey,
            certificate.GetECDsaPublicKey,
            certificate.GetECDiffieHellmanPublicKey,
        };

        string friendlyName = certificate.SignatureAlgorithm.FriendlyName ?? string.Empty;
        if (friendlyName is not { Length: > 0 })
        {
            return string.Empty;
        }

        int? keySize = producers
            .Select(producer => producer())
            .Cast<dynamic?>()
            .Where(publicKey => publicKey is not null)
            .Select(TryGetKeySize)
            .FirstOrDefault();

        StringBuilder builder = new();
        builder.Append(friendlyName);
        if (keySize.HasValue)
        {
            builder.Append($" ({keySize} bits)");
        }

        return builder.ToString();

        static int? TryGetKeySize(dynamic? value)
        {
            try
            {
                return value!.KeySize;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

#endif


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
