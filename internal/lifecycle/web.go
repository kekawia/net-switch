package lifecycle

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
)

//go:embed web/*
var browser embed.FS

func servePair(w http.ResponseWriter, r *http.Request, port int) {
	origin := fmt.Sprintf("127.0.0.1:%d", port)
	if r.Host != origin && r.Host != fmt.Sprintf("localhost:%d", port) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	name, content := "pair.html", "text/html; charset=utf-8"
	if r.URL.Path == "/pair.js" {
		name, content = "pair.js", "text/javascript; charset=utf-8"
	}
	if r.URL.Path == "/pair.css" {
		name, content = "pair.css", "text/css; charset=utf-8"
	}
	b, err := browser.ReadFile("web/" + name)
	if err != nil {
		http.Error(w, "Pairing page unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", content)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

// ServiceAsset adapts authentication and app-identity pinning at the serving
// boundary while leaving the frozen Node UI assets byte-identical. M5 will
// retire the legacy hash handoff.
func ServiceAsset(name string, b []byte) []byte {
	if name != "app.js" {
		return b
	}
	source := string(b)
	start := strings.Index(source, "function readToken() {")
	if start < 0 {
		panic("embedded UI readToken contract changed")
	}
	end := strings.Index(source[start:], "\n}\n")
	if start < 0 || end < 0 {
		panic("embedded UI readToken contract changed")
	}
	source = source[:start] + `function readToken() {
  const current = sessionStorage.getItem('token');
  if (!current) location.replace('/pair');
  return current;
}` + source[start+end+3:]
	replaceOnce := func(old, next, contract string) {
		if strings.Count(source, old) != 1 {
			panic("embedded UI " + contract + " contract changed")
		}
		source = strings.Replace(source, old, next, 1)
	}
	replaceOnce(
		"    const src = `/api/icon?key=${encodeURIComponent(app.key)}&token=${encodeURIComponent(token)}`;\n    return h('span', { class: 'app-icon has-image' }, h('img', { src, alt: '', width: 18, height: 18 }));",
		`    const image = h('img', { alt: '', width: 18, height: 18 });
    fetch('/api/icon?key=' + encodeURIComponent(app.key), { headers: { 'X-Token': token }, credentials: 'omit' })
      .then(response => { if (!response.ok) throw new Error('Icon unavailable'); return response.blob(); })
      .then(blob => { const url = URL.createObjectURL(blob); image.onload = image.onerror = () => URL.revokeObjectURL(url); image.src = url; })
      .catch(() => image.remove());
    return h('span', { class: 'app-icon has-image' }, image);`,
		"icon authentication",
	)
	replaceOnce("response = await fetch(path, {", "response = await fetch(path, {\n      credentials: 'omit',", "fetch credentials")
	replaceOnce(
		"state = await api('/api/app-line', { path: app.path, line });",
		"state = await api('/api/app-line', { path: app.identity ?? app.path, line });",
		"chooseLine identity",
	)
	replaceOnce(
		"const app = state.apps.find((item) => item.path.toLowerCase() === path.toLowerCase());",
		"const app = state.apps.find((item) => item.identity === path || item.key === path || (path.includes('\\\\') ? item.path.toLowerCase() === path.toLowerCase() : item.path === path));",
		"lineOfPath identity",
	)
	replaceOnce(
		"            const picked = pickedApp === app.path;\n            const current = lineOfPath(app.path);",
		"            const appTarget = app.identity ?? app.path;\n            const picked = pickedApp === appTarget;\n            const current = lineOfPath(appTarget);",
		"installed app target",
	)
	replaceOnce("'data-focus': `app-choice:${app.path}`,", "'data-focus': `app-choice:${appTarget}`,", "installed app focus")
	replaceOnce("pickedApp = picked ? null : app.path;", "pickedApp = picked ? null : appTarget;", "installed app selection")
	replaceOnce("'data-focus': `app-line:${app.path}:${line.id}`,", "'data-focus': `app-line:${appTarget}:${line.id}`,", "installed app line focus")
	replaceOnce(
		"const ok = await run('add-app', () => api('/api/app-line', { path: app.path, line: line.id }));",
		"const ok = await run('add-app', () => api('/api/app-line', { path: appTarget, line: line.id }));",
		"installed app pin",
	)
	replaceOnce(
		"state.apps.filter((app) => app.line).map((app) => [app.path, app.line]),",
		"state.apps.filter((app) => app.line).map((app) => [app.key, app.line]),",
		"apps panel signature",
	)
	return []byte(source)
}
