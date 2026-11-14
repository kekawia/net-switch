package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

func TestRPCStopAcknowledgementBeforeEOF(t *testing.T) {
	server, client := net.Pipe()
	rpc := NewRPC(client)
	defer rpc.Close()
	go func() {
		defer server.Close()
		scan := bufio.NewScanner(server)
		if !scan.Scan() {
			return
		}
		var request map[string]any
		_ = json.Unmarshal(scan.Bytes(), &request)
		_ = json.NewEncoder(server).Encode(map[string]any{"id": request["id"], "result": true})
	}()
	var stopped bool
	if err := rpc.Call(context.Background(), map[string]any{"method": "stop"}, &stopped); err != nil || !stopped {
		t.Fatal(stopped, err)
	}
}
func TestOwnerIsNeverFirstClient(t *testing.T) {
	for _, owner := range []Owner{{}, {User: "owner", Name: "Owner"}} {
		a := &Access{Owner: owner, Tokens: NewTokens()}
		for _, method := range []string{"session", "pair", "revoke", "routing", "signin", "desktop-connect", "desktop-result"} {
			if _, err := a.request(context.Background(), localipc.Peer{User: "stranger"}, false, "connection", controlRequest{Method: method}); err == nil {
				t.Fatalf("%s granted to stranger", method)
			}
		}
		if a.Owner != owner {
			t.Fatal("first client enrolled itself")
		}
	}
	a := &Access{Owner: Owner{User: "owner"}, Tokens: NewTokens()}
	if _, err := a.request(context.Background(), localipc.Peer{User: "owner"}, true, "connection", controlRequest{Method: "session"}); err == nil {
		t.Fatal("status pipe issued a token")
	}
}
func TestServiceAssetsDoNotPutCredentialsInURLs(t *testing.T) {
	source, err := assets.UI.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	result := string(ServiceAsset("app.js", source))
	for _, bad := range []string{"&token=", "location.hash.slice(1)"} {
		if strings.Contains(result, bad) {
			t.Fatalf("service asset retained %s", bad)
		}
	}
	if !strings.Contains(result, "credentials: 'omit'") {
		t.Fatal("browser still sends ambient credentials")
	}
	if !strings.Contains(string(source), "&token=") {
		t.Fatal("test did not exercise legacy icon source")
	}
	for _, want := range []string{
		"api('/api/app-line', { path: app.identity ?? app.path, line })",
		"api('/api/app-line', { path: appTarget, line: line.id })",
		"item.identity === path || item.key === path",
		"map((app) => [app.key, app.line])",
		"Saved data use was damaged and reset.",
		"Can\u2019t save data use right now.",
		"netswitch-session",
		"netswitch-ready",
		"netswitch-quit",
		"netswitch-refresh-token",
	} {
		if !strings.Contains(result, want) {
			t.Fatalf("service asset missing %q", want)
		}
	}
}
func TestDurableStorePrimaryAndBackup(t *testing.T) {
	if runtime.GOOS == "windows" && (os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted") {
		t.Skip("explicit Windows service-file ownership is tested on hosted runners")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	want := map[string]string{"engineInstanceId": "instance", "sha256": "hash"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".bak"} {
		var got map[string]string
		if err := Read(file, &got); err != nil || got["engineInstanceId"] != "instance" {
			t.Fatal(got, err)
		}
	}
}
func TestRemoteSnapshotRetainsFailureBeforeFirstAttachment(t *testing.T) {
	remote := NewRemote(context.Background(), func(string) {})
	remote.failInstance(errors.New("service could not start"))
	state := remote.Snapshot()
	if state.FailureID == "" || state.Status != "error" || state.Error == nil {
		t.Fatal("failed-start identity was lost", state)
	}
}

func TestRPCTimeoutDoesNotDisconnectOtherRequests(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	rpc := NewRPC(client)
	defer rpc.Close()
	go func() {
		scan := bufio.NewScanner(server)
		for scan.Scan() {
			var request map[string]any
			_ = json.Unmarshal(scan.Bytes(), &request)
			if request["method"] == "renew" {
				_ = json.NewEncoder(server).Encode(map[string]any{"id": request["id"], "result": true})
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := rpc.Call(ctx, map[string]any{"method": "slow-stats"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rpc.Call(ctx, map[string]any{"method": "renew"}, nil); err != nil {
		t.Fatal("a timed-out stats request broke the independent lease renewal:", err)
	}
}

type failedListener struct {
	conn *localipc.Conn
	err  error
}

func (l *failedListener) Accept(context.Context) (*localipc.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	return nil, l.err
}
func (*failedListener) Close() error { return nil }

func TestListenerFailureReleasesIdleClients(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	failure := errors.New("listener failed")
	listener := &failedListener{conn: &localipc.Conn{ReadWriteCloser: server}, err: failure}
	done := make(chan error, 1)
	go func() {
		done <- accept(context.Background(), listener, func(c *localipc.Conn) {
			defer c.Close()
			var b [1]byte
			_, _ = c.Read(b[:])
		}, func(string) {})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, failure) {
			t.Fatal("listener failure was hidden:", err)
		}
	case <-time.After(time.Second):
		client.Close()
		<-done
		t.Fatal("idle client hid the listener failure from service recovery")
	}
}

func TestServiceAppJSWebView2AndUsageErrorRuntime(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	source, err := assets.UI.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	transformed := ServiceAsset("app.js", source)
	harness := `
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const appCode = fs.readFileSync(0, 'utf8');

class Node {}
function matchesSimple(el, sel) {
  if (!el || !el.attributes) return false;
  const parts = sel.split(/\s+/).filter(Boolean);
  const last = parts[parts.length - 1];
  const tagMatch = /^[a-z0-9-]+/i.exec(last);
  if (tagMatch && el.tagName !== tagMatch[0].toUpperCase()) return false;
  for (const m of last.matchAll(/\.([a-z0-9_-]+)/gi)) {
    const classes = String(el.className || '').split(/\s+/);
    if (!classes.includes(m[1])) return false;
  }
  for (const m of last.matchAll(/\[([^\]=]+)(?:=['"]?([^\]'"]*)['"]?)?\]/g)) {
    if (m[2] !== undefined) {
      if (String(el.attributes[m[1]] ?? '') !== m[2]) return false;
    } else if (!(m[1] in el.attributes)) {
      return false;
    }
  }
  return true;
}
function findAll(root, sel, out = []) {
  for (const child of root.children || []) {
    if (matchesSimple(child, sel)) out.push(child);
    findAll(child, sel, out);
  }
  return out;
}
function makeElement(tag) {
  const listeners = new Map();
  const children = [];
  const dataset = {};
  const attrs = {};
  let text = '';
  const el = Object.assign(new Node(), {
    tagName: tag.toUpperCase(),
    dataset,
    attributes: attrs,
    children,
    style: {},
    className: '',
    hidden: false,
    disabled: false,
    open: false,
    innerHTML: '',
    classList: {
      toggle(c, force) {
        const set = new Set(String(el.className || '').split(/\s+/).filter(Boolean));
        const on = force === undefined ? !set.has(c) : Boolean(force);
        if (on) set.add(c); else set.delete(c);
        el.className = [...set].join(' ');
      },
      add(...cs) { cs.forEach((c) => el.classList.toggle(c, true)); },
      remove(...cs) { cs.forEach((c) => el.classList.toggle(c, false)); },
      contains(c) { return String(el.className || '').split(/\s+/).includes(c); },
    },
    setAttribute(k, v) {
      attrs[k] = String(v);
      if (k === 'data-kind') dataset.kind = String(v);
      if (k === 'class') el.className = String(v);
    },
    removeAttribute(k) {
      delete attrs[k];
      if (k === 'data-kind') delete dataset.kind;
    },
    hasAttribute(k) { return k in attrs; },
    hasChildNodes() { return children.length > 0; },
    getAttribute(k) { return attrs[k] ?? null; },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    dispatchEvent(type, ev = {}) {
      for (const fn of listeners.get(type) ?? []) fn(ev);
    },
    insertBefore(node, ref) {
      const idx = children.indexOf(node);
      if (idx >= 0) children.splice(idx, 1);
      if (!ref) { children.push(node); return node; }
      const refIdx = children.indexOf(ref);
      if (refIdx >= 0) children.splice(refIdx, 0, node);
      else children.push(node);
      return node;
    },
    append(...items) {
      for (const item of items) children.push(item);
    },
    appendChild(child) { children.push(child); return child; },
    replaceChildren(...items) { children.splice(0, children.length, ...items); },
    remove() {},
    focus() {},
    contains() { return false; },
    closest() { return null; },
    showModal() { el.open = true; },
    close() { el.open = false; },
    querySelector(sel) { return findAll(el, sel)[0] || null; },
    querySelectorAll(sel) { return findAll(el, sel); },
  });
  Object.defineProperty(el, 'textContent', {
    get() {
      return children.length ? children.map((c) => c.textContent || '').join('') : text;
    },
    set(v) {
      children.length = 0;
      text = String(v ?? '');
    },
  });
  return el;
}

const byId = new Map();
for (const id of ['routing-status','routing-toggle','lines','combine','notices','apps','empty','list-message','footer-note','open-settings','add-app','quit','panel']) {
  const e = makeElement('div');
  e.id = id;
  byId.set(id, e);
}
const document = {
  body: makeElement('body'),
  activeElement: null,
  getElementById(id) { return byId.get(id) || makeElement('div'); },
  querySelector() { return makeElement('div'); },
  createElement(tag) { return makeElement(tag); },
  createElementNS(_ns, tag) { return makeElement(tag); },
  createDocumentFragment() { return makeElement('#fragment'); },
  createTextNode(t) { return Object.assign(new Node(), { nodeType: 3, textContent: String(t) }); },
};

const posted = [];
const wvListeners = [];
const windowListeners = new Map();
const storage = new Map();
let replacedUrl = null;
const timers = new Map();
let nextTimer = 1;

const windowObj = {
  chrome: {
    webview: {
      postMessage(msg) { posted.push(JSON.parse(msg)); },
      addEventListener(type, fn) { if (type === 'message') wvListeners.push(fn); },
    },
  },
  addEventListener(type, fn) {
    if (!windowListeners.has(type)) windowListeners.set(type, []);
    windowListeners.get(type).push(fn);
  },
  matchMedia() { return { matches: false, addEventListener() {} }; },
};
windowObj.window = windowObj;

let stateCall = 0;
const setupState = { wifiBlocked: false, cableNotDefault: false, keepBothConnected: false, changed: { cableDefault: false, keepBoth: false } };
const sampleLine = {
  id: 'l1', alias: 'Ethernet', label: 'Fiber', kind: 'wired', main: true,
  connected: true, problem: null, ping: 12, connections: 1, carrying: true,
  target: 'l1', rate: { down: 1024, up: 512 }, ssid: null, metered: false,
  strict: false, cap: null, usage: { bytes: 0, periodStart: '2026-11-01T00:00:00.000Z' },
  exhausted: false, weight: 1, share: null,
};
function makeState(usageError) {
  return {
    mode: 'tun', version: '1.0.0', routing: { status: 'on', wanted: true, measuring: true },
    lines: [sampleLine], combine: { on: false, active: false, mode: 'auto', shares: {} },
    setup: setupState, settings: { checkForUpdates: false, ipv6: 'off' },
    apps: [], outside: [], events: [], usageError,
  };
}

function collectText(node) {
  if (!node) return '';
  if (typeof node.textContent === 'string' && (!node.children || node.children.length === 0)) return node.textContent;
  return (node.children || []).map(collectText).join(' ');
}

const sandbox = {
  Node,
  window: windowObj,
  document,
  sessionStorage: {
    getItem(k) { return storage.has(k) ? storage.get(k) : null; },
    setItem(k, v) { storage.set(k, String(v)); },
    removeItem(k) { storage.delete(k); },
  },
  location: { hash: '', pathname: '/', replace(u) { replacedUrl = u; } },
  history: { replaceState() {} },
  matchMedia: windowObj.matchMedia,
  URL: { createObjectURL() { return 'blob:1'; }, revokeObjectURL() {} },
  setTimeout(fn) { const id = nextTimer++; timers.set(id, fn); return id; },
  clearTimeout(id) { timers.delete(id); },
  Map, Set, Date, Math, Number, String, Boolean, Array, Object, JSON, Error, RegExp, Promise, console,
  fetch: async (path, opts = {}) => {
    assert.equal(opts.credentials, 'omit');
    if (path === '/api/quit') {
      assert.equal(opts.headers['X-Token'], 'tok2');
      return { ok: true, status: 200, async json() { return { ok: true }; } };
    }
    stateCall++;
    if (stateCall === 1) {
      assert.equal(opts.headers['X-Token'], 'tok1');
      return {
        ok: true, status: 200,
        async json() {
          return makeState('Corrupt usage history preserved as usage.corrupt-123; accounting continues: bad json');
        },
      };
    }
    if (stateCall === 2) {
      assert.equal(opts.headers['X-Token'], 'tok1');
      return {
        ok: true, status: 200,
        async json() {
          return makeState('Usage history unavailable; routing continues: access denied');
        },
      };
    }
    if (stateCall === 3) {
      return { ok: false, status: 401, async json() { return { error: 'Unauthorized' }; } };
    }
    assert.equal(opts.headers['X-Token'], 'tok2');
    return {
      ok: true, status: 200,
      async json() {
        return makeState(null);
      },
    };
  },
};

vm.runInNewContext(appCode, sandbox);

(async () => {
  assert.equal(replacedUrl, null, 'WebView2 must not redirect to /pair immediately');
  assert.deepEqual(posted, [{ type: 'netswitch-ready' }]);
  for (const fn of wvListeners) fn({ data: JSON.stringify({ type: 'netswitch-session', token: 'tok1' }) });
  await new Promise((r) => setTimeout(r, 20));
  const noticesEl = byId.get('notices');
  assert.equal(noticesEl.children.length, 1);
  assert.equal(noticesEl.children[0].dataset.kind, 'status');
  const txt1 = collectText(noticesEl.children[0]);
  assert.match(txt1, /Saved data use was damaged and reset\./);
  assert.doesNotMatch(txt1, /corrupt-123/);

  const pollFn = Array.from(timers.values()).pop();
  assert(pollFn, 'poll timer scheduled');
  timers.clear();
  pollFn();
  await new Promise((r) => setTimeout(r, 20));
  assert.match(collectText(noticesEl.children[0]), /Can’t save data use right now\./);

  const pollFn2 = Array.from(timers.values()).pop();
  assert(pollFn2, 'second poll timer scheduled');
  timers.clear();
  pollFn2();
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(posted.slice(-1)[0], { type: 'netswitch-refresh-token' });

  for (const fn of wvListeners) fn({ data: { type: 'netswitch-session', token: 'tok2' } });
  await new Promise((r) => setTimeout(r, 20));

  byId.get('quit').dispatchEvent('click');
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(posted.slice(-1)[0], { type: 'netswitch-quit' });
})().catch((err) => { console.error(err); process.exit(1); });
`
	cmd := exec.Command("node", "--max-old-space-size=2048", "-e", harness)
	cmd.Stdin = strings.NewReader(string(transformed))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node runtime check failed: %v\n%s", err, out)
	}
}
