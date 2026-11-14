package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

const MessageLimit = 1 << 20
const Outstanding = 16

type ProxyCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProxyTestSpec struct {
	Line     platform.ProxyLine `json:"line"`
	Username string             `json:"username,omitempty"`
	Password string             `json:"password,omitempty"`
	Target   string             `json:"target,omitempty"`
}

type Request struct {
	ID       string           `json:"id"`
	Method   string           `json:"method"`
	Instance string           `json:"engineInstanceId"`
	Epoch    uint64           `json:"epoch"`
	Revision *policy.Revision `json:"revision,omitempty"`
	Cursor   string           `json:"cursor,omitempty"`
	Receipt  string           `json:"receipt,omitempty"`
	// All asks flows for every admitted flow, unresolved ones included.
	All           bool                       `json:"all,omitempty"`
	OpID          string                     `json:"opId,omitempty"`
	Selector      flows.Selector             `json:"selector,omitempty"`
	StartedBefore uint64                     `json:"startedBefore,omitempty"`
	Line          string                     `json:"line,omitempty"`
	Operator      string                     `json:"operator,omitempty"`
	Target        string                     `json:"target,omitempty"`
	Quick         bool                       `json:"quick,omitempty"`
	Custom        bool                       `json:"custom,omitempty"`
	Listen        string                     `json:"listen,omitempty"`
	App           string                     `json:"app,omitempty"`
	Credentials   map[string]ProxyCredential `json:"credentials,omitempty"`
	ProxyTest     *ProxyTestSpec             `json:"proxyTest,omitempty"`
	Fault         json.RawMessage            `json:"fault,omitempty"`
}
type Reply struct {
	ID         string `json:"id"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	stop       bool
	afterWrite func()
}
type Event = flowapi.Event

func Decode(b []byte) (Request, error) {
	var r Request
	if len(b) > MessageLimit {
		return r, errors.New("message exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, errors.New("trailing JSON")
	}
	if r.ID == "" || len(r.ID) > 128 || len(r.OpID) > 128 || len(r.Cursor) > 128 || len(r.Receipt) > 128 || len(r.App) > 512 || len(r.Line) > 64 || len(r.Operator) > 256 || len(r.Target) > 256 || len(r.Listen) > 128 || len(r.Credentials) > 255 {
		return r, errors.New("invalid request fields")
	}
	for k, cred := range r.Credentials {
		if k == "" || len(k) > 128 || len(cred.Username) > 255 || len(cred.Password) > 255 {
			return r, errors.New("invalid request fields")
		}
	}
	if pt := r.ProxyTest; pt != nil {
		if len(pt.Line.Protocol) > 16 || len(pt.Line.Server) > 256 || len(pt.Line.ServerName) > 256 || len(pt.Line.Carrier) > 64 || len(pt.Username) > 255 || len(pt.Password) > 255 || len(pt.Target) > 256 {
			return r, errors.New("invalid request fields")
		}
	}
	return r, nil
}
