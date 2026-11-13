package desktop

import "time"

const (
	NotifyPerLineSeconds = 30
	NotifyGapSeconds     = 4
)

// LineEvent represents one server-emitted line state transition.
type LineEvent struct {
	ID     string
	Kind   string
	LineID string
	Text   string
}

// Notice is a debounced notification ready to show to the user.
type Notice struct {
	EventID string
	LineID  string
	Title   string
	Text    string
	Warning bool
}

// EventNotifier selects and rate-limits line events so each is shown at most
// once, pre-existing events on startup are skipped, and flapping lines emit
// only their newest transition per 30-second window.
type EventNotifier struct {
	seen      map[string]bool
	waiting   map[string]LineEvent
	order     []string
	shownAt   map[string]time.Time
	lastShown time.Time
	primed    bool
}

// EventsFromState extracts line events from a /api/state response. Returns nil
// when the state carries no events array.
func EventsFromState(state map[string]any) ([]LineEvent, bool) {
	if state == nil {
		return nil, false
	}
	raw, ok := state["events"]
	if !ok || raw == nil {
		return nil, false
	}
	switch raw.(type) {
	case []any, []map[string]any:
	default:
		return nil, false
	}
	items := itemMaps(state, "events")
	events := make([]LineEvent, 0, len(items))
	for _, item := range items {
		events = append(events, LineEvent{
			ID:     textVal(item, "id"),
			Kind:   textVal(item, "kind"),
			LineID: textVal(item, "lineId"),
			Text:   textVal(item, "text"),
		})
	}
	return events, true
}

// Read ingests the latest events snapshot. When enabled is false, any pending
// unsent events are discarded, while seen tracking continues.
func (n *EventNotifier) Read(events []LineEvent, hasEvents bool, enabled bool) {
	if n.seen == nil {
		n.seen = map[string]bool{}
		n.waiting = map[string]LineEvent{}
		n.shownAt = map[string]time.Time{}
	}
	if !enabled {
		n.waiting = map[string]LineEvent{}
		n.order = nil
	}
	if !hasEvents {
		n.primed = true
		return
	}
	current := make(map[string]bool, len(events))
	for _, item := range events {
		if item.ID == "" {
			continue
		}
		current[item.ID] = true
		if n.seen[item.ID] {
			continue
		}
		n.seen[item.ID] = true
		if !n.primed || !enabled || item.Text == "" {
			continue
		}
		line := item.LineID
		if _, exists := n.waiting[line]; !exists {
			n.order = append(n.order, line)
		}
		n.waiting[line] = item
	}
	for id := range n.seen {
		if !current[id] {
			delete(n.seen, id)
		}
	}
	n.primed = true
}

// Next returns the next deliverable notification at now, or nil if rate limits
// hold it back or the queue is empty.
func (n *EventNotifier) Next(now time.Time) *Notice {
	if !n.lastShown.IsZero() && now.Sub(n.lastShown).Seconds() < NotifyGapSeconds {
		return nil
	}
	for i := 0; i < len(n.order); i++ {
		line := n.order[i]
		if last, ok := n.shownAt[line]; ok && now.Sub(last).Seconds() < NotifyPerLineSeconds {
			continue
		}
		item := n.waiting[line]
		delete(n.waiting, line)
		n.order = append(n.order[:i], n.order[i+1:]...)
		n.shownAt[line] = now
		n.lastShown = now
		return &Notice{
			EventID: item.ID,
			LineID:  item.LineID,
			Title:   noticeTitle(item.Kind),
			Text:    item.Text,
			Warning: item.Kind == "down" || item.Kind == "exhausted",
		}
	}
	return nil
}

func noticeTitle(kind string) string {
	switch kind {
	case "down":
		return "Line down"
	case "up":
		return "Line back"
	case "exhausted":
		return "Data cap reached"
	case "cap-reset":
		return "Data cap reset"
	default:
		return "Net Switch"
	}
}
