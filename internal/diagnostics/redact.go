// Package diagnostics builds the problem report a person can read and attach
// to an issue: Net Switch's newest service log lines with personal details
// replaced. Nothing is sent anywhere; the report is text the caller saves.
package diagnostics

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Options name what the logs cannot reveal on their own.
type Options struct {
	// Users are account names to replace wherever they appear as words, such
	// as the owner's account. Names found in profile paths are added.
	Users []string
	// Computer is this PC's name.
	Computer string
	// Keep are public addresses that identify no one and that a reader needs
	// to see, such as the internet-test addresses Net Switch connects to.
	Keep []netip.Addr
}

// DefaultKeep are the addresses Net Switch itself uses for its internet
// tests (control/poll.go, linecheck, the IPv6 probe). They are public
// resolvers, not anything about the person.
var DefaultKeep = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("8.8.8.8"),
	netip.MustParseAddr("9.9.9.9"),
	netip.MustParseAddr("2606:4700:4700::1111"),
}

var (
	// A profile folder followed by more path, so the name may hold spaces.
	windowsProfile = regexp.MustCompile(`(?i)([a-z]:[\\/]+users[\\/]+)([^\\/:*?"<>|\r\n]{1,64}?)([\\/])`)
	// A profile folder at the end of a path: no spaces, to stay in the path.
	windowsProfileEnd = regexp.MustCompile(`(?i)([a-z]:[\\/]+users[\\/]+)([^\\/:*?"<>|\r\n\t ,;()'\[\]]{1,64})`)
	linuxHome         = regexp.MustCompile(`(/home/)([^/\s:'"()\[\],;]{1,64})`)
	email             = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}`)
	accountSID        = regexp.MustCompile(`\bS-1-5-21(?:-\d+){3,4}\b`)
	guid              = regexp.MustCompile(`\{?\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b\}?`)
	mac               = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b`)
	ipv4              = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Candidates only: anything with two colons. ParseAddr decides, so
	// times like 03:19:07.123 stay as they are.
	ipv6            = regexp.MustCompile(`(?i)[0-9a-f]*:[0-9a-f]*:[0-9a-f:.]*(?:%[0-9a-z_.-]+)?`)
	placeholder     = regexp.MustCompile(`^\[[a-z-]+-\d+\]$`)
	placeholderSpan = regexp.MustCompile(`\[(?:computer|[a-z-]+-\d+)\]`)
	cgnat           = netip.MustParsePrefix("100.64.0.0/10")
	benchmark       = netip.MustParsePrefix("198.18.0.0/15") // Net Switch's own tunnel
)

// Shared profile folders say nothing about a person.
var sharedProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true}

// Redact replaces user and computer names, email addresses, public IP
// addresses, hardware addresses, account SIDs and GUIDs with placeholders.
// Each distinct value keeps one placeholder for the whole text, so [user-1]
// is the same account and [public-ip-2] the same address everywhere.
func Redact(text string, o Options) string {
	r := redactor{seen: map[string]map[string]string{}, keep: map[netip.Addr]bool{}}
	for _, addr := range append(append([]netip.Addr{}, DefaultKeep...), o.Keep...) {
		r.keep[addr.Unmap()] = true
	}
	for _, name := range o.Users {
		r.user(name) // the owner is [user-1] in every report
	}
	users := r.learnUsers(text, o.Users)
	text = windowsProfile.ReplaceAllStringFunc(text, func(m string) string {
		g := windowsProfile.FindStringSubmatch(m)
		return g[1] + r.user(g[2]) + g[3]
	})
	text = windowsProfileEnd.ReplaceAllStringFunc(text, func(m string) string {
		g := windowsProfileEnd.FindStringSubmatch(m)
		return g[1] + r.user(g[2])
	})
	text = linuxHome.ReplaceAllStringFunc(text, func(m string) string {
		g := linuxHome.FindStringSubmatch(m)
		return g[1] + r.user(g[2])
	})
	text = email.ReplaceAllStringFunc(text, func(m string) string { return r.label("email", m) })
	if name := strings.TrimSpace(o.Computer); utf8.RuneCountInString(name) >= 2 {
		text = replaceWords(text, name, func(string) string { return "[computer]" })
	}
	for _, name := range users {
		text = replaceWords(text, name, r.user)
	}
	text = accountSID.ReplaceAllStringFunc(text, func(m string) string { return r.label("sid", m) })
	text = guid.ReplaceAllStringFunc(text, func(m string) string { return r.label("guid", strings.Trim(m, "{}")) })
	text = mac.ReplaceAllStringFunc(text, func(m string) string { return r.label("mac", strings.ReplaceAll(m, "-", ":")) })
	text = ipv4.ReplaceAllStringFunc(text, r.address)
	return ipv6.ReplaceAllStringFunc(text, r.address)
}

type redactor struct {
	seen map[string]map[string]string // kind -> lowercased value -> placeholder
	keep map[netip.Addr]bool
}

func (r *redactor) label(kind, value string) string {
	values := r.seen[kind]
	if values == nil {
		values = map[string]string{}
		r.seen[kind] = values
	}
	key := strings.ToLower(value)
	if p, ok := values[key]; ok {
		return p
	}
	p := fmt.Sprintf("[%s-%d]", kind, len(values)+1)
	values[key] = p
	return p
}

func (r *redactor) user(name string) string {
	trimmed := strings.TrimSpace(name)
	if placeholder.MatchString(trimmed) || sharedProfiles[strings.ToLower(trimmed)] {
		return name
	}
	return r.label("user", trimmed)
}

// learnUsers collects every account name before any replacement, so a name
// is replaced as a word even where it appears before its first profile path.
// Longest first, so "Ayoub Smith" goes before "Ayoub".
func (r *redactor) learnUsers(text string, given []string) []string {
	found := map[string]string{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if utf8.RuneCountInString(name) < 3 || placeholder.MatchString(name) || sharedProfiles[strings.ToLower(name)] {
			return
		}
		if _, ok := found[strings.ToLower(name)]; !ok {
			found[strings.ToLower(name)] = name
		}
	}
	for _, name := range given {
		add(name)
	}
	for _, re := range []*regexp.Regexp{windowsProfile, windowsProfileEnd, linuxHome} {
		for _, g := range re.FindAllStringSubmatch(text, -1) {
			add(g[2])
		}
	}
	names := make([]string, 0, len(found))
	for _, name := range found {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	return names
}

// replaceWords replaces whole-word, case-insensitive occurrences of name,
// never inside a placeholder already written (an account called "user" must
// not turn [user-1] into [[user-1]-1]). Go's \b only knows ASCII letters, so
// the edges are checked by hand.
func replaceWords(text, name string, with func(string) string) string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name))
	written := placeholderSpan.FindAllStringIndex(text, -1)
	var out strings.Builder
	last, span := 0, 0
	for _, m := range re.FindAllStringIndex(text, -1) {
		for span < len(written) && written[span][1] <= m[0] {
			span++
		}
		if m[0] < last || !wordEdge(text, m[0], m[1]) || span < len(written) && written[span][0] < m[1] {
			continue
		}
		out.WriteString(text[last:m[0]])
		out.WriteString(with(text[m[0]:m[1]]))
		last = m[1]
	}
	out.WriteString(text[last:])
	return out.String()
}

func wordEdge(text string, start, end int) bool {
	before, _ := utf8.DecodeLastRuneInString(text[:start])
	after, _ := utf8.DecodeRuneInString(text[end:])
	inWord := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }
	return (start == 0 || !inWord(before)) && (end == len(text) || !inWord(after))
}

// address replaces a public address. Private, loopback, link-local, CGNAT,
// benchmark (the tunnel), multicast and documentation addresses say which
// line or adapter something is about and identify no one, so they stay.
func (r *redactor) address(m string) string {
	addr, err := netip.ParseAddr(m)
	if err != nil {
		return m
	}
	addr = addr.Unmap()
	if r.keep[addr] || !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnat.Contains(addr) || benchmark.Contains(addr) || documentation(addr) {
		return m
	}
	return r.label("public-ip", addr.WithZone("").String())
}

var documentationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func documentation(addr netip.Addr) bool {
	for _, p := range documentationPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
