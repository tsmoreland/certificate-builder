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

using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace TSMoreland.Certificates;

#if !NET6_0_OR_GREATER

/// <summary>
/// See the net6.0 implementation of System.Security.Cryptography.PemEncoding, this
/// code is based on that with just enough modifications to make it compatible with
/// net48 and net472
/// </summary>
internal static class PemEncoding
{
#if true

    private const string PreEbPrefix = "-----BEGIN ";
    private const string PostEbPrefix = "-----END ";
    private const string Ending = "-----";
    private const int EncodedLineLength = 64;

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

            bool isSpaceOrHyphen = c == ' ' || c == '-';

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsBase64Character(char ch)
    {
        uint c = (uint)ch;
        return c == '+' || c == '/' ||
               c - '0' < 10 || c - 'A' < 26 || c - 'a' < 26;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsWhiteSpaceCharacter(char ch)
    {
        // Match white space characters from Convert.Base64
        return ch is ' ' or '\t' or '\n' or '\r';
    }

    /// <summary>
    /// Determines the length of a PEM-encoded value, in characters,
    /// given the length of a label and binary data.
    /// </summary>
    /// <param name="labelLength">
    /// The length of the label, in characters.
    /// </param>
    /// <param name="dataLength">
    /// The length of the data, in bytes.
    /// </param>
    /// <returns>
    /// The number of characters in the encoded PEM.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    ///   <paramref name="labelLength"/> is a negative value.
    ///   <para>
    ///       -or-
    ///   </para>
    ///   <paramref name="dataLength"/> is a negative value.
    ///   <para>
    ///       -or-
    ///   </para>
    ///   <paramref name="labelLength"/> exceeds the maximum possible label length.
    ///   <para>
    ///       -or-
    ///   </para>
    ///   <paramref name="dataLength"/> exceeds the maximum possible encoded data length.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The length of the PEM-encoded value is larger than <see cref="int.MaxValue"/>.
    /// </exception>
    public static int GetEncodedSize(int labelLength, int dataLength)
    {
        // The largest possible label is MaxLabelSize - when included in the posteb
        // and preeb lines new lines, assuming the base64 content is empty.
        //     -----BEGIN {char * MaxLabelSize}-----\n
        //     -----END {char * MaxLabelSize}-----
        const int maxLabelSize = 1_073_741_808;

        // The largest possible binary value to fit in a padded base64 string
        // is 1,610,612,733 bytes. RFC 7468 states:
        //   Generators MUST wrap the base64-encoded lines so that each line
        //   consists of exactly 64 characters except for the final line
        // We need to account for new line characters, every 64 characters.
        // This works out to 1,585,834,053 maximum bytes in data when wrapping
        // is accounted for assuming an empty label.
        const int maxDataLength = 1_585_834_053;

        if (labelLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(labelLength), "needs positive number");
        }

        if (dataLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(dataLength), "needs positive number");
        }

        if (labelLength > maxLabelSize)
        {
            throw new ArgumentOutOfRangeException(nameof(labelLength), "needs positive number");
        }

        if (dataLength > maxDataLength)
        {
            throw new ArgumentOutOfRangeException(nameof(dataLength), "needs positive number");
        }

        int preebLength = PreEbPrefix.Length + labelLength + Ending.Length;
        int postebLength = PostEbPrefix.Length + labelLength + Ending.Length;
        int totalEncapLength = preebLength + postebLength + 1; //Add one for newline after preeb

        // dataLength is already known to not overflow here
        int encodedDataLength = ((dataLength + 2) / 3) << 2;
        int lineCount = Math.DivRem(encodedDataLength, EncodedLineLength, out int remainder);

        if (remainder > 0)
        {
            lineCount++;
        }

        int encodedDataLengthWithBreaks = encodedDataLength + lineCount;

        if (int.MaxValue - encodedDataLengthWithBreaks < totalEncapLength)
        {
            throw new ArgumentException("Encoding size too large");
        }

        return encodedDataLengthWithBreaks + totalEncapLength;
    }

    /// <summary>
    /// Tries to write the provided data and label as PEM-encoded data into
    /// a provided buffer.
    /// </summary>
    /// <param name="label">
    /// The label to write.
    /// </param>
    /// <param name="data">
    /// The data to write.
    /// </param>
    /// <param name="destination">
    /// The buffer to receive the PEM-encoded text.
    /// </param>
    /// <param name="charsWritten">
    /// When this method returns, this parameter contains the number of characters
    /// written to <paramref name="destination"/>. This parameter is treated
    /// as uninitialized.
    /// </param>
    /// <returns>
    /// <c>true</c> if <paramref name="destination"/> is large enough to contain
    /// the PEM-encoded text, otherwise <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method always wraps the base-64 encoded text to 64 characters, per the
    /// recommended wrapping of IETF RFC 7468. Unix-style line endings are used for line breaks.
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
    public static bool TryWrite(string label, byte[] data, char[] destination, out int charsWritten)
    {
        static int WriteAttempt(string str, char[] dest, int offset)
        {
            str.CopyTo(0, dest, offset, str.Length); 
            return str.Length;
        }

        static int WriteBase64(byte[] bytes, char[] dest, int offset)
        {
            try
            {
                return Convert.ToBase64CharArray(bytes, 0, bytes.Length, dest, offset);
            }
            catch (Exception)
            {
                throw new ArgumentException(null, nameof(destination));
            }

        }

        if (!IsValidLabel(label))
        {
            throw new ArgumentException("invalid label", nameof(label));
        }

        const string newLine = "\n";
        const int bytesPerLine = 48;
        int encodedSize = GetEncodedSize(label.Length, data.Length);

        if (destination.Length < encodedSize)
        {
            charsWritten = 0;
            return false;
        }

        charsWritten = 0;
        charsWritten += WriteAttempt(PreEbPrefix, destination, charsWritten);
        charsWritten += WriteAttempt(label, destination, charsWritten);
        charsWritten += WriteAttempt(Ending, destination, charsWritten);
        charsWritten += WriteAttempt(newLine, destination, charsWritten);

        byte[] remainingData = data;
        int offset = 0;
        while (remainingData.Length >= bytesPerLine)
        {
            byte[] bytes = new byte[bytesPerLine];

            for (int i = offset, j = 0; j < bytesPerLine; i++, j++)
            {
                bytes[j] = remainingData[i];
            }
            offset += bytesPerLine;

            charsWritten += WriteBase64(bytes, destination, charsWritten);
            charsWritten += WriteAttempt(newLine, destination, charsWritten);
        }

        Debug.Assert(remainingData.Length < bytesPerLine);

        if (remainingData.Length  - offset > 0)
        {
            byte[] bytes = new byte[remainingData.Length  - offset];
            for (int i = offset, j = 0; j < remainingData.Length  - offset; i++, j++)
            {
                bytes[j] = remainingData[i];
            }

            charsWritten += WriteBase64(bytes, destination, charsWritten);
            charsWritten += WriteAttempt(newLine, destination, charsWritten);
        }

        charsWritten += WriteAttempt(PostEbPrefix, destination, charsWritten);
        charsWritten += WriteAttempt(label, destination, charsWritten);
        charsWritten += WriteAttempt(Ending, destination, charsWritten);

        return true;
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

        int encodedSize = GetEncodedSize(label.Length, data.Length);
        char[] buffer = new char[encodedSize];

        if (!TryWrite(label, data, buffer, out int charsWritten))
        {
            Debug.Fail("TryWrite failed with a pre-sized buffer");
            throw new ArgumentException(null, nameof(data));
        }

        Debug.Assert(charsWritten == encodedSize);
        return buffer;
    }
#endif
}

#endif
