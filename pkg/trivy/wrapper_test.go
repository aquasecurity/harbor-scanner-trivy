package trivy

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testData string = `[{
	"Target": "knqyf263/vuln-image (alpine 3.7.1)",
	"Vulnerabilities": [{
		"VulnerabilityID": "CVE-2018-6543",
		"PkgName": "binutils",
		"InstalledVersion": "2.30-r1",
		"FixedVersion": "2.30-r2",
		"Title": "binutils:  integer overflow in load_specific_debug_section function in objdump.c",
		"Description": "In GNU Binutils 2.30, there's an integer overflow in the function load_specific_debug_section() in objdump.c, which results in malloc() with 0 size. A crafted ELF file allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.",
		"Severity": "MEDIUM",
		"References": [
			"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00072.html",
			"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00008.html",
			"http://www.securityfocus.com/bid/102985",
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543",
			"https://security.gentoo.org/glsa/201811-17",
			"https://sourceware.org/bugzilla/show_bug.cgi?id=22769"
		]
	}]
},
{
	"Target": "node-app/package-lock.json",
	"Vulnerabilities": [{
		"VulnerabilityID": "CVE-2019-11358",
		"PkgName": "jquery",
		"InstalledVersion": "3.3.9",
		"FixedVersion": "\u003e=3.4.0",
		"Title": "js-jquery: prototype pollution in object's prototype leading to denial of service or remote code execution or property injection",
		"Description": "jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.",
		"Severity": "MEDIUM",
		"References": [
			"http://packetstormsecurity.com/files/152787/dotCMS-5.1.1-Vulnerable-Dependencies.html",
			"http://packetstormsecurity.com/files/153237/RetireJS-CORS-Issue-Script-Execution.html"

		]
	}]
},
{
	"Target": "php-app/composer.lock",
	"Vulnerabilities": [{
		"VulnerabilityID": "CVE-2016-5385",
		"PkgName": "guzzlehttp/guzzle",
		"InstalledVersion": "6.2.0",
		"FixedVersion": "4.2.4, 5.3.1, 6.2.1",
		"Title": "PHP: sets environmental variable based on user supplied Proxy request header",
		"Description": "PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request, as demonstrated by (1) an application that makes a getenv('HTTP_PROXY') call or (2) a CGI configuration of PHP, aka an \"httpoxy\" issue.",
		"Severity": "MEDIUM",
		"References": [
			"http://linux.oracle.com/cve/CVE-2016-5385.html",
			"http://linux.oracle.com/errata/ELSA-2016-1613.html"
		]
	}]
},
{
	"Target": "python-app/Pipfile.lock",
	"Vulnerabilities": null
}
]`

func TestWrapperParseScanReports(t *testing.T) {
	f, err := ioutil.TempFile("", "trivy_test_report-*.json")
	require.NoError(t, err)
	_, err = f.WriteString(testData)
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	w := &wrapper{}
	report, err := w.parseScanReports(f)
	require.NoError(t, err)
	assert.Equal(t, len(report.Vulnerabilities), 3)
	assert.Equal(t, report.Target, "knqyf263/vuln-image (alpine 3.7.1)")
}

func TestWrapperParseScanReportsWithEmptyData(t *testing.T) {
	f, err := ioutil.TempFile("", "trivy_test_report-*.json")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	w := &wrapper{}
	_, err = w.parseScanReports(f)
	require.Error(t, err)
}
