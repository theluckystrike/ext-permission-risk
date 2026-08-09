// Package extpermissionrisk maps a Chrome / Manifest V3 extension permission
// string (activeTab, tabs, cookies, <all_urls>, or a host match-pattern like
// *://*.example.com/*) to a risk level — Low, Medium, or High — together with
// a short, plain-English explanation of what that permission lets the
// extension actually do.
//
// This is the Go port of the ext-permission-risk Rust crate and the
// permission-classification table behind the zovo.one Chrome-extension
// privacy & security scanner at https://zovo.one/.
//
// The same three-tier model, with a longer plain-English write-up of what
// each permission actually exposes, is published at
// https://zovo.one/permissions - useful when you need to explain a High
// verdict to a non-engineer. The tiers there are not identical to this
// table: a few borderline permissions, cookies among them, are placed one
// tier lower on the site because they are gated by host access in practice.
//
// Quick example:
//
//	info, ok := extpermissionrisk.RiskOf("cookies")
//	fmt.Println(ok, info.Level, info.Description)
//
//	overall := extpermissionrisk.HighestRisk([]string{"activeTab", "storage", "cookies"})
//	fmt.Println(overall) // High
package extpermissionrisk

// RiskLevel is the three-tier classification used by the zovo.one scanner.
// Ordered Low < Medium < High so it can be compared and used to pick a max.
type RiskLevel int

const (
	// RiskUnknown is returned when no recognised permission is present.
	RiskUnknown RiskLevel = iota
	// RiskLow: no persistent broad access; scoped to a user gesture or the
	// extension's own sandbox.
	RiskLow
	// RiskMedium: sensitive access (history, downloads, per-site host
	// permissions, clipboard) but not a blanket global grant.
	RiskMedium
	// RiskHigh: broad, persistent, cross-origin or sensitive-system access.
	RiskHigh
)

// String returns an uppercase label suitable for badges / UI chips.
func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "LOW"
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// PermissionRisk is a single permission → risk mapping: the permission token
// exactly as it appears in a manifest's permissions / host_permissions
// array, its risk level, and a concise plain-English description.
type PermissionRisk struct {
	Permission  string
	Level       RiskLevel
	Description string
}

// permissionTable is the full curated permission → risk table. Ordered
// roughly Low → Medium → High for readability. Host match-pattern rules
// (<all_urls>, *://*/*, scheme wildcards) are included because they appear
// in host_permissions and are the single biggest driver of extension risk.
var permissionTable = []PermissionRisk{
	// ---- LOW ----
	{Permission: "activeTab", Level: RiskLow, Description: "Grants temporary access to the current tab only when the user explicitly clicks the extension's action. No persistent background access to any site."},
	{Permission: "contextMenus", Level: RiskLow, Description: "Adds items to the browser's right-click context menu. No page content access by itself."},
	{Permission: "storage", Level: RiskLow, Description: "Stores extension data locally (synced/local). Confined to the extension's own sandbox; cannot read site data."},
	{Permission: "alarms", Level: RiskLow, Description: "Schedules code to run at a future time. No content access by itself."},
	{Permission: "idle", Level: RiskLow, Description: "Detects when the machine is idle or locked. No page content access."},
	{Permission: "notifications", Level: RiskLow, Description: "Shows desktop notifications. No page content access."},
	{Permission: "power", Level: RiskLow, Description: "Keeps the screen or system awake. No content access."},
	{Permission: "tts", Level: RiskLow, Description: "Text-to-speech output. No content access."},
	{Permission: "unlimitedStorage", Level: RiskLow, Description: "Removes the extension storage quota. No extra site access."},
	{Permission: "declarativeNetRequest", Level: RiskLow, Description: "Blocks or modifies network requests via static rules (the MV3 content-blocker path). Less powerful than webRequest blocking, but can still read request URLs."},

	// ---- MEDIUM ----
	{Permission: "bookmarks", Level: RiskMedium, Description: "Reads and modifies the user's full bookmark tree."},
	{Permission: "history", Level: RiskMedium, Description: "Reads and clears the user's full browsing history."},
	{Permission: "downloads", Level: RiskMedium, Description: "Initiates, monitors, and opens downloads; can open arbitrary files from the download shelf."},
	{Permission: "downloads.open", Level: RiskMedium, Description: "Opens downloaded files on disk. Combined with a hostile download this can execute local content."},
	{Permission: "geolocation", Level: RiskMedium, Description: "Reads the user's GPS / IP-derived location (subject to a per-site permission prompt)."},
	{Permission: "clipboardWrite", Level: RiskMedium, Description: "Writes to the system clipboard. Can overwrite a copied password or inject pasted content."},
	{Permission: "clipboardRead", Level: RiskMedium, Description: "Reads the system clipboard, which frequently contains copied passwords, tokens, or private text."},
	{Permission: "identity", Level: RiskMedium, Description: "Triggers OAuth sign-in and obtains the user's signed-in account email / profile and an auth token."},
	{Permission: "management", Level: RiskMedium, Description: "Lists, enables, disables, and uninstalls other installed extensions."},
	{Permission: "tabs", Level: RiskMedium, Description: "Reads the URL and title of every open tab and receives tab-update events. Effectively full browsing-session visibility."},
	{Permission: "tabGroups", Level: RiskMedium, Description: "Reads and modifies tab groups, exposing which sites the user clusters together."},
	{Permission: "topSites", Level: RiskMedium, Description: "Reads the user's most-visited sites (the new-tab shortcuts)."},
	{Permission: "sessions", Level: RiskMedium, Description: "Reads recently closed tabs and windows across devices."},
	{Permission: "pageCapture", Level: RiskMedium, Description: "Saves the current page as an MHTML archive, capturing rendered content."},
	{Permission: "search", Level: RiskMedium, Description: "Sets the default search provider and issues queries."},

	// ---- HIGH ----
	{Permission: "cookies", Level: RiskHigh, Description: "Reads and modifies all cookies for any site the extension has host access to, including session and auth cookies."},
	{Permission: "webRequest", Level: RiskHigh, Description: "Observes (and in MV2 could block) every network request and response, exposing full URLs, headers, and bodies including credentials."},
	{Permission: "debugger", Level: RiskHigh, Description: "Attaches the Chrome DevTools Protocol to a tab, giving full DOM, network, and JS execution control — effectively total control of the page."},
	{Permission: "nativeMessaging", Level: RiskHigh, Description: "Talks to a native application installed on the user's machine. Escapes the browser sandbox entirely."},
	{Permission: "fileSystem", Level: RiskHigh, Description: "Reads and writes files outside the browser sandbox (where granted by the platform)."},
	{Permission: "<all_urls>", Level: RiskHigh, Description: "Requests host access to every site on the web. Combined with content scripts this means any page's content, forms, and credentials can be read."},
	{Permission: "*://*/*", Level: RiskHigh, Description: "Match pattern granting host access to every http/https URL. Equivalent in effect to <all_urls> for normal browsing."},
	{Permission: "http://*/*", Level: RiskHigh, Description: "Host access to every plain-http URL, including login pages and intranet sites."},
	{Permission: "https://*/*", Level: RiskHigh, Description: "Host access to every secure URL on the web."},
	{Permission: "file:///*", Level: RiskHigh, Description: "Host access to local files via the file:// scheme, subject to the 'allow access to file URLs' toggle."},
	{Permission: "proxy", Level: RiskHigh, Description: "Configures the browser's proxy settings. A hostile extension can redirect all traffic through an attacker-controlled server."},
	{Permission: "privacy", Level: RiskHigh, Description: "Reads and changes privacy-related browser settings (do-not-track, third-party cookies, hyperlink auditing)."},
	{Permission: "system.cpu", Level: RiskHigh, Description: "Reads detailed CPU metadata useful for device fingerprinting."},
	{Permission: "system.memory", Level: RiskHigh, Description: "Reads physical memory capacity, a device-fingerprinting signal."},
	{Permission: "system.storage", Level: RiskHigh, Description: "Reads attached storage device metadata and can eject devices."},
	{Permission: "system.network", Level: RiskHigh, Description: "Reads network interface metadata exposing the local network topology."},
	{Permission: "system.display", Level: RiskHigh, Description: "Reads display metadata (resolution, DPI) usable for fingerprinting."},
	{Permission: "vpnProvider", Level: RiskHigh, Description: "Configures a VPN (ChromeOS), which can redirect and intercept all network traffic."},
	{Permission: "enterprise.networkingAttributes", Level: RiskHigh, Description: "Reads detailed network attributes (ChromeOS enterprise), exposing internal network identity."},
	{Permission: "webNavigation", Level: RiskHigh, Description: "Receives the full navigation events of every frame in every tab, including the URL of every frame and redirect."},
	{Permission: "scripting", Level: RiskHigh, Description: "Injects arbitrary JavaScript into pages for which the extension has host permission — full page control at runtime (MV3 successor to tabs.executeScript)."},
	{Permission: "contentSettings", Level: RiskHigh, Description: "Reads and modifies per-site content settings (cookies, javascript, plugins, mic, camera) for every origin."},
}

// AllPermissions returns the full curated permission → risk table.
func AllPermissions() []PermissionRisk {
	out := make([]PermissionRisk, len(permissionTable))
	copy(out, permissionTable)
	return out
}

// RiskOf looks up the risk classification for a single manifest permission
// string. It returns (zero, false) for tokens not in the curated table —
// unknown permissions are reported as unknown, never silently classified as
// High.
func RiskOf(permission string) (PermissionRisk, bool) {
	for _, p := range permissionTable {
		if p.Permission == permission {
			return p, true
		}
	}
	return PermissionRisk{}, false
}

// RiskOfOrPattern classifies a single entry from a manifest's permissions /
// host_permissions array, recognising host match-patterns in addition to
// named tokens.
//
//   - Known named tokens are looked up directly.
//   - Any *://, https://, or file:// match pattern is classified as Medium
//     (site-scoped host access).
//   - Anything else is returned as Low with an "unclassified, review
//     manually" description.
func RiskOfOrPattern(token string) PermissionRisk {
	if found, ok := RiskOf(token); ok {
		return found
	}
	if IsHostPattern(token) {
		return PermissionRisk{
			Permission:  "host-pattern",
			Level:       RiskMedium,
			Description: "A scoped host match-pattern (e.g. *://*.example.com/*). Grants the extension read and script access to the matching sites only — less broad than <all_urls>, still sensitive.",
		}
	}
	return PermissionRisk{
		Permission:  "unknown",
		Level:       RiskLow,
		Description: "This permission is not in the curated risk table. It may be a private, enterprise, or partner API; treat as unclassified until manually reviewed.",
	}
}

// IsHostPattern reports whether token looks like a Manifest V3 host
// match-pattern (scheme://...) rather than a named permission token.
// The special <all_urls> token is handled by the table directly and is
// therefore NOT considered a pattern here.
func IsHostPattern(token string) bool {
	if token == "" {
		return false
	}
	return contains(token, "://")
}

// HighestRisk returns the single highest risk level among the given manifest
// permission tokens. Unknown tokens are ignored. It returns RiskUnknown if
// no recognised permission is present.
func HighestRisk(permissions []string) RiskLevel {
	max := RiskUnknown
	for _, p := range permissions {
		if found, ok := RiskOf(p); ok {
			if found.Level > max {
				max = found.Level
			}
		}
	}
	return max
}

// contains is a tiny dependency-free substring check.
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
