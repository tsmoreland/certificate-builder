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

namespace TSMoreland.Certificates.Test;

public sealed class SubjectNameBuilderTest
{

    private const string CommonName = "unit-test";
    private const string OrganizationUnit = "unit-test.org unit";
    private const string Organization = "unit-test.org";
    private const string City = "Tuktoyaktuk";
    private const string State = "Northwest Territories";
    private const string Country = "CA";


    [TestCase(null)]
    [TestCase("")]
    public void Constructor_ThrowsArgumentException_WhenCommonNameIsNullOrEmpty(string value)
    {
        ArgumentException? ex = Assert
            .Throws<ArgumentException>(() => _ =
                new SubjectNameBuilder(value, OrganizationUnit, Organization, City, State, Country));
        Assert.That(ex!.ParamName, Is.EqualTo("CommonName"));
    }

    [TestCase(null)]
    [TestCase("")]
    public void Constructor_DoesNotThrow_WhenOrganizationUnitIsNullOrEmpty(string value)
    {
        Assert.DoesNotThrow(() => _ = new SubjectNameBuilder(CommonName, value, Organization, City, State, Country));
    }

}
