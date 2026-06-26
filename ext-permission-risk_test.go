package extpermissionrisk

import "testing"

func TestKnownPermissionsClassified(t *testing.T) {
	// Every entry in the table must round-trip through RiskOf.
	for _, entry := range permissionTable {
		got, ok := RiskOf(entry.Permission)
		if !ok {
			t.Fatalf("table entry %q not found by RiskOf", entry.Permission)
		}
		if got.Level != entry.Level {
			t.Fatalf("%q level mismatch: got %v want %v", entry.Permission, got.Level, entry.Level)
		}
		if got.Description == "" {
			t.Fatalf("%q has empty description", entry.Permission)
		}
		if len(got.Description) < 20 {
			t.Fatalf("%q description too short: %q", entry.Permission, got.Description)
		}
	}
}

func TestHighRiskPermissions(t *testing.T) {
	for _, high := range []string{"<all_urls>", "cookies", "debugger", "nativeMessaging", "webRequest", "scripting"} {
		info, ok := RiskOf(high)
		if !ok {
			t.Fatalf("missing %q", high)
		}
		if info.Level != RiskHigh {
			t.Fatalf("%q should be High, got %v", high, info.Level)
		}
	}
}

func TestLowRiskPermissions(t *testing.T) {
	for _, low := range []string{"activeTab", "storage", "alarms", "contextMenus", "notifications"} {
		info, ok := RiskOf(low)
		if !ok {
			t.Fatalf("missing %q", low)
		}
		if info.Level != RiskLow {
			t.Fatalf("%q should be Low, got %v", low, info.Level)
		}
	}
}

func TestMediumRiskPermissions(t *testing.T) {
	for _, med := range []string{"tabs", "history", "bookmarks", "clipboardRead", "downloads"} {
		info, ok := RiskOf(med)
		if !ok {
			t.Fatalf("missing %q", med)
		}
		if info.Level != RiskMedium {
			t.Fatalf("%q should be Medium, got %v", med, info.Level)
		}
	}
}

func TestUnknownPermissionIsUnknownNotHigh(t *testing.T) {
	// Critical correctness property: unknown tokens never silently escalate
	// to High.
	_, ok := RiskOf("totally-fake-permission-xyz")
	if ok {
		t.Fatal("unknown permission should not be found")
	}
	_, ok = RiskOf("")
	if ok {
		t.Fatal("empty string should not be found")
	}
}

func TestIsHostPattern(t *testing.T) {
	cases := map[string]bool{
		"https://*.example.com/*": true,
		"*://*/*":                 true,
		"file:///*":               true,
		"http://example.com/":     true,
		"tabs":                    false,
		"cookies":                 false,
		"":                        false,
		"<all_urls>":              false, // named token, not a pattern
	}
	for in, want := range cases {
		if got := IsHostPattern(in); got != want {
			t.Fatalf("IsHostPattern(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRiskOfOrPatternKnownToken(t *testing.T) {
	cookies := RiskOfOrPattern("cookies")
	if cookies.Level != RiskHigh {
		t.Fatalf("cookies should be High, got %v", cookies.Level)
	}
	if cookies.Permission != "cookies" {
		t.Fatalf("permission name should be passed through, got %q", cookies.Permission)
	}
}

func TestRiskOfOrPatternScopedHost(t *testing.T) {
	scoped := RiskOfOrPattern("https://*.example.com/*")
	if scoped.Level != RiskMedium {
		t.Fatalf("scoped host pattern should be Medium, got %v", scoped.Level)
	}
	if !contains(scoped.Description, "host") {
		t.Fatalf("description should mention host, got %q", scoped.Description)
	}
}

func TestRiskOfOrPatternUnknown(t *testing.T) {
	u := RiskOfOrPattern("somePrivateEnterpriseApi")
	if u.Level != RiskLow {
		t.Fatalf("unknown should be Low (unclassified), got %v", u.Level)
	}
	if u.Permission != "unknown" {
		t.Fatalf("permission name should be 'unknown', got %q", u.Permission)
	}
	if !contains(u.Description, "not in the curated") {
		t.Fatalf("description should mention unclassified, got %q", u.Description)
	}
}

func TestHighestRisk(t *testing.T) {
	if got := HighestRisk([]string{"activeTab", "storage", "cookies", "tabs"}); got != RiskHigh {
		t.Fatalf("highest should be High, got %v", got)
	}
	if got := HighestRisk([]string{"tabs", "history"}); got != RiskMedium {
		t.Fatalf("highest should be Medium, got %v", got)
	}
	if got := HighestRisk([]string{"activeTab"}); got != RiskLow {
		t.Fatalf("highest should be Low, got %v", got)
	}
	if got := HighestRisk([]string{"???", "!!!"}); got != RiskUnknown {
		t.Fatalf("highest should be Unknown, got %v", got)
	}
	if got := HighestRisk(nil); got != RiskUnknown {
		t.Fatalf("nil input should be Unknown, got %v", got)
	}
}

func TestRiskLevelOrdering(t *testing.T) {
	// RiskLow < RiskMedium < RiskHigh — required for HighestRisk's max.
	if !(RiskLow < RiskMedium) {
		t.Fatal("Low must be < Medium")
	}
	if !(RiskMedium < RiskHigh) {
		t.Fatal("Medium must be < High")
	}
	if !(RiskLow < RiskHigh) {
		t.Fatal("Low must be < High")
	}
}

func TestRiskLevelString(t *testing.T) {
	if got := RiskLow.String(); got != "LOW" {
		t.Fatalf("RiskLow.String() = %q, want LOW", got)
	}
	if got := RiskMedium.String(); got != "MEDIUM" {
		t.Fatalf("RiskMedium.String() = %q, want MEDIUM", got)
	}
	if got := RiskHigh.String(); got != "HIGH" {
		t.Fatalf("RiskHigh.String() = %q, want HIGH", got)
	}
	if got := RiskUnknown.String(); got != "UNKNOWN" {
		t.Fatalf("RiskUnknown.String() = %q, want UNKNOWN", got)
	}
}

func TestAllPermissionsBreadth(t *testing.T) {
	all := AllPermissions()
	if len(all) < 30 {
		t.Fatalf("table only has %d entries", len(all))
	}
	high, med, low := 0, 0, 0
	for _, p := range all {
		switch p.Level {
		case RiskHigh:
			high++
		case RiskMedium:
			med++
		case RiskLow:
			low++
		}
	}
	if high < 10 {
		t.Fatalf("need >=10 High entries, got %d", high)
	}
	if med < 8 {
		t.Fatalf("need >=8 Medium entries, got %d", med)
	}
	if low < 5 {
		t.Fatalf("need >=5 Low entries, got %d", low)
	}
}

func TestAllPermissionsIsACopy(t *testing.T) {
	// AllPermissions must return a copy so callers cannot mutate the table.
	a := AllPermissions()
	a[0].Permission = "MUTATED"
	b := AllPermissions()
	if b[0].Permission == "MUTATED" {
		t.Fatal("AllPermissions returned a slice aliasing the package table")
	}
}

func TestContains(t *testing.T) {
	if !contains("https://example.com", "://") {
		t.Fatal("contains should find ://")
	}
	if contains("tabs", "://") {
		t.Fatal("contains should not find :// in tabs")
	}
	if !contains("anything", "") {
		t.Fatal("empty substring should match")
	}
	if contains("", "://") {
		t.Fatal("empty string should not contain ://")
	}
}
