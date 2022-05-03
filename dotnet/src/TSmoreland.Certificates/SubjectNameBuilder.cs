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

using System.Text;

namespace TSMoreland.Certificates;

/// <summary>
/// Subject Name
/// </summary>
public sealed record SubjectNameBuilder(
    string CommonName,
    string? OrganizationUnit = null,
    string? Organization = null,
    string? City = null,
    string? State = null,
    string? Country = null)
{
    /// <summary>
    /// Common Name component of the subject name
    /// </summary>
    public string CommonName { get; init; } = CommonName is { Length : > 0 }
        ? CommonName
        : throw new ArgumentException("Invalid common name, cannot be empty", nameof(CommonName));

    /// <summary>
    ///  Build Subject Name from provided parameters
    /// </summary>
    /// <returns></returns>
    public string Build()
    {
        StringBuilder builder = new();
        builder.Append($"CN={CommonName}");

        if (OrganizationUnit is { Length: > 0 })
        {
            builder.Append($",OU={OrganizationUnit}");
        }

        if (Organization is { Length: > 0 })
        {
            builder.Append($",O={Organization}");
        }

        if (City is { Length: > 0 })
        {
            builder.Append($",L={City}");
        }

        if (State is { Length: > 0 })
        {
            builder.Append($",S={State}");
        }

        if (Country is { Length: > 0 })
        {
            builder.Append($",C={Country}");
        }

        return builder.ToString();
    }
}
