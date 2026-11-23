package diagnostics

import (
	"net/netip"
	"strings"
	"testing"
)

// Each case is a line shaped like the real Control and engine logs.
func TestRedactReplacesPersonalDetails(t *testing.T) {
	o := Options{Users: []string{"Dana"}, Computer: "DESKTOP-TEST01"}
	for _, tc := range []struct{ name, in, want string }{
		{"owner account", `Control ready (PID 27884); owner=DESKTOP-TEST01\Dana`, `Control ready (PID 27884); owner=[computer]\[user-1]`},
		{"profile path", `reconnect c:\users\dana\appdata\roaming\app\9424831ad51c\app.exe: closed 1`, `reconnect c:\users\[user-1]\appdata\roaming\app\9424831ad51c\app.exe: closed 1`},
		{"forward slashes", `C:/Users/Dana/AppData/x.exe`, `C:/Users/[user-1]/AppData/x.exe`},
		{"profile with a space", `C:\Users\Dana Smith\AppData\x.exe and Dana Smith`, `C:\Users\[user-2]\AppData\x.exe and [user-2]`},
		{"profile at the end of a path", `profile C:\Users\dana moved`, `profile C:\Users\[user-1] moved`},
		{"linux home", `/home/robin/.config/netswitch`, `/home/[user-2]/.config/netswitch`},
		{"email", `signed in as dana.k@example.org.`, `signed in as [email-1].`},
		{"account SID", `owner S-1-5-21-1111111111-2222222222-3333333333-1001 and S-1-5-18`, `owner [sid-1] and S-1-5-18`},
		{"GUID", `adapter {4D36E972-E325-11CE-BFC1-08002BE10318} again 4d36e972-e325-11ce-bfc1-08002be10318`, `adapter [guid-1] again [guid-1]`},
		{"MAC", `00-1A-2B-3C-4D-5E is 00:1a:2b:3c:4d:5e`, `[mac-1] is [mac-1]`},
		{"public IPv4", `dial 93.184.216.34:443 then 93.184.216.35`, `dial [public-ip-1]:443 then [public-ip-2]`},
		{"public IPv6", `dial [2a00:1450:4007:80f::200e]:443`, `dial [[public-ip-1]]:443`},
		{"IPv4-mapped IPv6", `from ::ffff:93.184.216.34`, `from ::ffff:[public-ip-1]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A leading line fixes [user-1] as Dana, as the owner line does in a report.
			got := Redact("owner=Dana\n"+tc.in, o)
			if got != "owner=[user-1]\n"+tc.want {
				t.Fatalf("\n got: %s\nwant: %s", got, "owner=[user-1]\n"+tc.want)
			}
		})
	}
}

// What a reader needs and that identifies no one stays as it is.
func TestRedactKeepsWhatIsNotPersonal(t *testing.T) {
	for _, line := range []string{
		`2026-11-23T03:19:07.1234Z 2026/11/23 04:19:07 native outcome instance=1d7d6508071d513f53be83dceacb67e7 reason=stop`,
		`192.168.1.11:1>9.9.9.9:443 via 10.0.0.2 and 172.16.4.1`,
		`probe 1.1.1.1:443 and 8.8.8.8:443 and [2606:4700:4700::1111]:443`,
		`tunnel 198.18.0.1/30, CGNAT 100.64.1.2, loopback 127.0.0.1 and ::1, any 0.0.0.0`,
		`link fe80::1%12, ULA fd12:3456::1, multicast 224.0.0.251 and ff02::fb`,
		`docs 192.0.2.7 and 2001:db8::5`,
		`Windows 11 (10.0.26300), version 0.99.4, took 13.86 s at 05:52:15`,
		`C:\Users\Public\Desktop and C:\Users\Default\NTUSER.DAT`,
		`error=<nil> forced=false completed=true`,
	} {
		if got := Redact(line, Options{}); got != line {
			t.Errorf("changed a line with nothing personal\n got: %s\nwant: %s", got, line)
		}
	}
}

func TestRedactNamesOnlyAsWholeWords(t *testing.T) {
	got := Redact("Ann went to announce Ann's plan; José and josé", Options{Users: []string{"Ann", "José"}})
	if want := "[user-1] went to announce [user-1]'s plan; [user-2] and [user-2]"; got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}

// An account named like a placeholder word must not rewrite placeholders.
func TestRedactNeverRewritesItsOwnPlaceholders(t *testing.T) {
	got := Redact(`C:\Users\user\x.exe as user on computer 93.184.216.34`, Options{Users: []string{"user", "computer", "public"}, Computer: "ip"})
	if strings.Contains(got, "[[") || strings.Contains(got, "]]") || strings.Contains(got, "-1]-") {
		t.Fatal("placeholder rewritten:", got)
	}
	if want := `C:\Users\[user-1]\x.exe as [user-1] on [user-2] [public-ip-1]`; got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}

func TestRedactKeepsConfiguredAddresses(t *testing.T) {
	keep := Options{Keep: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	if got := Redact("test site 93.184.216.34:443", keep); got != "test site 93.184.216.34:443" {
		t.Fatal("configured test address redacted:", got)
	}
}
