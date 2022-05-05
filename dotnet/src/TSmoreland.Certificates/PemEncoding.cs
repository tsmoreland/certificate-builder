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

using System.Text;

namespace TSMoreland.Certificates;

#if !NET6_0_OR_GREATER

/// <summary>
/// See the net6.0 implementation of System.Security.Cryptography.PemEncoding, this
/// code is based on that with just enough modifications to make it compatible with
/// net48 and net472
/// </summary>
internal static class PemEncoding
{
    private const string PreEbPrefix = "-----BEGIN ";
    private const string PostEbPrefix = "-----END ";
    private const string Ending = "-----";

    private static bool IsValidLabel(string data)
    {
        static bool IsLabelChar(char c) => (uint)(c - 0x21u) <= 0x5du && c != '-';

        // Empty labels are permitted per RFC 7468.
        if (data is { Length: 0 })
        {
            return true;
        }

        // The first character must be a labelchar, so initialize to false
        bool previousIsLabelChar = false;

        foreach (char c in data)
        {
            if (IsLabelChar(c))
            {
                previousIsLabelChar = true;
                continue;
            }

            bool isSpaceOrHyphen = c is ' ' or '-';

            // IETF RFC 7468 states that every character in a label must
            // be a labelchar, and each labelchar may have zero or one
            // preceding space or hyphen, except the first labelchar.
            // If this character is not a space or hyphen, then this characer
            // is invalid.
            // If it is a space or hyphen, and the previous character was
            // also not a labelchar (another hyphen or space), then we have
            // two consecutive spaces or hyphens which is is invalid.
            if (!isSpaceOrHyphen || !previousIsLabelChar)
            {
                return false;
            }

            previousIsLabelChar = false;
        }

        // The last character must also be a labelchar. It cannot be a
        // hyphen or space since these are only allowed to precede
        // a labelchar.
        return previousIsLabelChar;
    }

    /// <summary>
    /// Creates an encoded PEM with the given label and data.
    /// </summary>
    /// <param name="label">
    /// The label to encode.
    /// </param>
    /// <param name="data">
    /// The data to encode.
    /// </param>
    /// <returns>
    /// A character array of the encoded PEM.
    /// </returns>
    /// <remarks>
    /// This method always wraps the base-64 encoded text to 64 characters, per the
    /// recommended wrapping of RFC-7468. Unix-style line endings are used for line breaks.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    ///   <paramref name="label"/> exceeds the maximum possible label length.
    ///   <para>
    ///       -or-
    ///   </para>
    ///   <paramref name="data"/> exceeds the maximum possible encoded data length.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The resulting PEM-encoded text is larger than <see cref="int.MaxValue"/>.
    ///   <para>
    ///       - or -
    ///   </para>
    /// <paramref name="label"/> contains invalid characters.
    /// </exception>
    public static char[] Write(string label, byte[] data)
    {
        if (!IsValidLabel(label))
        {
            throw new ArgumentException("Invalid label", nameof(label));
        }

        const int bytesPerLine = 48;
        StringBuilder builder = new();

        builder.Append($"{PreEbPrefix}{label}{Ending}\n");
        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            builder
                .Append(Convert.ToBase64String(data, i, Math.Min(bytesPerLine, data.Length - i)))
                .Append('\n');
        }
        builder.Append($"{PostEbPrefix}{label}{Ending}\n");

        return builder.ToString().ToCharArray();
    }
}

#endif
