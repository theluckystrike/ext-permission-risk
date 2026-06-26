# ext-permission-risk

[![Go Reference](https://pkg.go.dev/badge/github.com/theluckystrike/ext-permission-risk.svg)](https://pkg.go.dev/github.com/theluckystrike/ext-permission-risk)

Map a Chrome / **Manifest V3** extension permission string — `activeTab`,
`tabs`, `cookies`, `<all_urls>`, or a host match-pattern like
`*://*.example.com/*` — to a **risk level** (`Low` / `Medium` / `High`)
with a short, plain-English explanation of what that permission actually
grants. Pure, dependency-free Go.

This is the Go port of the
[`ext-permission-risk`](https://crates.io/crates/ext-permission-risk) Rust
crate, and the permission-classification table behind the
[**zovo.one**](https://zovo.one/) Chrome-extension **privacy &amp; security
scanner**, which audits the permissions requested by any installed extension
and flags the ones that can read your data across every site.

## Why permission risk matters

Chrome extensions request permissions in their `manifest.json` under two
keys — `permissions` (named API tokens like `tabs`, `cookies`) and
`host_permissions` (match-patterns granting content-script access to
specific sites). Two extensions that both "just change your new tab page"
can request wildly different access: one asks for `storage`, the other for
`<all_urls>` + `cookies` + `webRequest`. The latter can read every password
you type, on every site, forever. The permission string is the single best
signal for whether an extension is safe to install — this package turns that
signal into a label.

## Install

```sh
go get github.com/theluckystrike/ext-permission-risk
```

## Quick example

```go
package main

import (
	"fmt"

	extpermissionrisk "github.com/theluckystrike/ext-permission-risk"
)

func main() {
	// Named token lookup.
	info, ok := extpermissionrisk.RiskOf("cookies")
	fmt.Println(ok, info.Level, info.Description)
	// true HIGH Reads and modifies all cookies for any site the extension
	//           has host access to, including session and auth cookies.

	// activeTab is the least-privileged tab-access alternative.
	low, _ := extpermissionrisk.RiskOf("activeTab")
	fmt.Println(low.Level) // LOW

	// Host match-patterns are recognised and classified as Medium.
	scoped := extpermissionrisk.RiskOfOrPattern("https://*.example.com/*")
	fmt.Println(scoped.Level) // MEDIUM

	// Compute the single highest risk across a whole manifest.
	overall := extpermissionrisk.HighestRisk([]string{"activeTab", "storage", "cookies", "tabs"})
	fmt.Println(overall) // HIGH
}
```

## API

| Function | Description |
| --- | --- |
| `RiskOf(permission string) (PermissionRisk, bool)` | Look up a named permission. `(zero, false)` if unknown. |
| `RiskOfOrPattern(token string) PermissionRisk` | Classify a token, recognising host match-patterns. |
| `IsHostPattern(token string) bool` | Heuristic: is this a `scheme://...` match-pattern? |
| `HighestRisk(permissions []string) RiskLevel` | The max risk level across a manifest's tokens. |
| `AllPermissions() []PermissionRisk` | A copy of the full curated table. |

### Types

| Type | Description |
| --- | --- |
| `RiskLevel` | `RiskUnknown`, `RiskLow`, `RiskMedium`, `RiskHigh` (ordered). |
| `PermissionRisk` | `{ Permission, Level, Description }` — one table row. |

## Design choices

- **Unknown ≠ High.** A token not in the table is surfaced as *unclassified*
  (`RiskLow` with a "review manually" note), never silently escalated to
  High. False alarms erode trust; the scanner tells you what it knows.
- **Host patterns are Medium, `<all_urls>` is High.** A scoped
  `*://*.example.com/*` grants access to one domain family and is
  meaningfully less broad than blanket access to the entire web.
- **Zero dependencies.** Standard library only.

## License

MIT.

## Links

- **zovo.one** — the Chrome-extension privacy &amp; security scanner powered
  by this table: <https://zovo.one/>
- Rust crate: <https://crates.io/crates/ext-permission-risk>
- Package docs: <https://pkg.go.dev/github.com/theluckystrike/ext-permission-risk>
