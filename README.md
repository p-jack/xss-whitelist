# xss-whitelist

A whitelist of safe HTML tags and attributes to help prevent XSS attacks.

```TypeScript
import { XSSWhitelist, XSSWhitelistError } from "xss-whitelist"

let ok:boolean

// Check if a tag is allowed:
ok = XSSWhitelist.allow("a") // true
ok = XSSWhitelist.allow("script") // false

// Check if an attribute value is allowed:
ok = XSSWhitelist.allow("a", "href", "https://example.com") // true
ok = XSSWhitelist.allow("a", "href", "javascript:alert(1)") // false
ok = XSSWhitelist.allow("a", "onclick", "alert(1)") // false

// Use .raise to throw a descriptive error instead:
XSSWhitelist.raise("a", "href", "javascript:alert(1)")
// XSSWhitelistError - not allowing a.href: invalid protocol javascript:

// Add a new tag and its attributes to the whitelist:
XSSWhitelist.add("object", ["archive"])

// Add the default URL rules to a new attribute:
XSSWhitelist.addHandler("data-url", XSSWhitelist.urlHandler)

// By default, only https: URLs are allowed.
// (Non-encrypted http: is allowed, but only for localhost
// for development purposes.)
// You can also allow additional protocols if needed:
XSSWhitelist.addProtocol("sftp:")

// add custom validation rules to an attribute
XSSWhitelist.addHandler("data-foo",
(tag:string, attr:string, value?:string) => {
  if (tag !== "div") {
    throw new XSSWhitelistError(tag, attr, "only valid on divs!")
  }
  if (value === undefined) {
    throw new XSSWhitelistError(tag, attr, "must specify a value")
  }
  return
})
```
