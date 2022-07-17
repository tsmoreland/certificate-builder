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
/// <see cref="X509Certificate2"/> Factory implementation
/// </summary>
public static class CertificateFactory
{
    /// <summary>
    /// Builds a self-signed <see cref="X509Certificate2"/> returning the certificate and
    /// a signing request (in bytes) which can be used
    /// </summary>
    /// <param name="extendedSignedCertificateSettings">certificate settings used to construct the certificate</param>
    public static SigningRequestCertificatePair Build(ExtendedSignedCertificateSettings extendedSignedCertificateSettings)
    {
        ThrowIfArgumentNull(extendedSignedCertificateSettings, nameof(extendedSignedCertificateSettings));

        (
            string subjectName,
            int keySizeInBits,
            DateTime? notBefore,
            DateTime? notAfter,
            IEnumerable<string> alternateNames,
            IEnumerable<Oid> additionalKeyUsages,
            _,
            X509KeyUsageFlags usageFlags,
            bool critical
        ) = extendedSignedCertificateSettings;

        using RSA rsa = RSA.Create(keySizeInBits);

        CertificateRequest request = new(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions
            .Add(new X509KeyUsageExtension(usageFlags, critical));

        request.CertificateExtensions
            .Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false,
                pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions
            .Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        SubjectAlternativeNameBuilder subjectAlternativeNameBuilder = new();
        foreach (string alternateName in alternateNames)
        {
            subjectAlternativeNameBuilder.AddDnsName(alternateName);
        }

        request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

        OidCollection collection = new();
        foreach (Oid keyUsage in additionalKeyUsages)
        {
            collection.Add(keyUsage);
        }

        request.CertificateExtensions
            .Add(new X509EnhancedKeyUsageExtension(collection, true));

        byte[] requestBytes = request.CreateSigningRequest();

        X509Certificate2 selfSigned = request.CreateSelfSigned(notBefore ?? DateTime.UtcNow, notAfter ?? DateTime.UtcNow.AddYears(1));

        return new SigningRequestCertificatePair(requestBytes, selfSigned);
    }

    /// <summary>
    /// Build Root and Timestamping authority
    /// </summary>
    /// <param name="settings"></param>
    /// <param name="timestampSettings"></param>
    /// <returns></returns>
    public static (X509Certificate2 Root, X509Certificate2 TimestampingCert)  Build(CertificateSettings settings, SignedCertificateSettings timestampSettings)
    {
        ThrowIfArgumentNull(settings, nameof(settings));
        ThrowIfArgumentNull(timestampSettings, nameof(timestampSettings));

        using RSA parentRsa = RSA.Create(settings.KeySizeInBits);
        using RSA timestampingRsa = RSA.Create(timestampSettings.KeySizeInBits);

        CertificateRequest parentRequest = BuildParentRequest(parentRsa, settings.SubjectName);

        X509Certificate2 parent = parentRequest.CreateSelfSigned(
            settings.NotBefore ?? DateTime.UtcNow.Subtract(TimeSpan.FromDays(7)),
            settings.NotAfter ?? DateTime.UtcNow.AddYears(2));

        CertificateRequest timestampingRequest =
            BuildTimestampingRequest(timestampingRsa, timestampSettings.SubjectName);


        X509Certificate2 timestamping = timestampingRequest.Create(
            parent,
            timestampSettings.NotBefore ?? DateTime.UtcNow.Subtract(TimeSpan.FromDays(1)),
            timestampSettings.NotAfter ?? DateTime.UtcNow.AddYears(1),
            timestampSettings.SerialNumber);

        return (parent, timestamping);
    }

    /// <summary>
    /// Build Signed certificate, signed witht he given issue
    /// </summary>
    public static X509Certificate2 BuildSignedCertificate(X509Certificate2 issuer, ExtendedSignedCertificateSettings settings)
    {
        ThrowIfArgumentNull(issuer, nameof(issuer));
        ThrowIfArgumentNull(settings, nameof(settings));

        (
            string subjectName,
            int keySizeInBits,
            DateTime? notBefore,
            DateTime? notAfter,
            IEnumerable<string> alternateNames,
            IEnumerable<Oid> additionalKeyUsages,
            byte[] serialNumber,
            X509KeyUsageFlags usageFlags,
            bool critical
        ) = settings;

        using RSA rsa = RSA.Create(keySizeInBits);

        CertificateRequest request = new(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions
            .Add(new X509KeyUsageExtension(usageFlags, critical));

        request.CertificateExtensions
            .Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false,
                pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions
            .Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        SubjectAlternativeNameBuilder subjectAlternativeNameBuilder = new();
        foreach (string alternateName in alternateNames)
        {
            subjectAlternativeNameBuilder.AddDnsName(alternateName);
        }

        request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

        OidCollection collection = new();
        foreach (Oid keyUsage in additionalKeyUsages)
        {
            collection.Add(keyUsage);
        }

        request.CertificateExtensions
            .Add(new X509EnhancedKeyUsageExtension(collection, true));

        return request.Create(
            issuer,
            notBefore ?? DateTime.UtcNow.Subtract(TimeSpan.FromDays(1)),
            notAfter ?? DateTime.UtcNow.AddYears(1),
            serialNumber);
    }

    private static CertificateRequest BuildParentRequest(in RSA parentRsa, string subjectName)
    {
        CertificateRequest parentRequest = new(
            subjectName,
            parentRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        parentRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        parentRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(parentRequest.PublicKey, false));

        return parentRequest;
    }

    private static CertificateRequest BuildTimestampingRequest(in RSA rsa, string subjectName)
    {
        CertificateRequest request = new (
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { OidFactory.BuildTimestampingReferenceInfo() },
                true));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }


}
