import { describe, expect, test  } from "vitest"
import { XSSWhitelist, XSSWhitelistError } from "./index"

const raise = XSSWhitelist.raise

describe("add/has", () => {
  describe("new tag", () => {
    test("no attrs", () => {
      expect(() => { raise("iframe") }).toThrow("not allowing tag iframe: not in tag whitelist")
      expect(() => { raise("iframe", "src", "https://a.c") }).toThrow("not allowing iframe.src: not in tag whitelist")
      XSSWhitelist.add("iframe", [])
      raise("iframe")
      raise("iframe", "id")
      raise("iframe", "data-foo")
      expect(() => { raise("iframe", "src", "https://a.c") }).toThrow("not allowing iframe.src: not in attr whitelist")
    })
    test("with addrs", () => {
      expect(() => { raise("script") }).toThrow("not allowing tag script: not in tag whitelist")
      expect(() => { raise("script", "src", "https://a.c") }).toThrow("not allowing script.src: not in tag whitelist")
      XSSWhitelist.add("script", ["src"])
      raise("script")
      raise("script", "id")
      raise("script", "data-foo")
      raise("script", "src", "https://a.c")
      expect(() => { raise("script", "src") }).toThrow("not allowing script.src: no value given for dangerous URL attribute")
      expect(() => { raise("script", "src", "javascript://alert(1)") }).toThrow("not allowing script.src: invalid protocol javascript:")
    })
  })
  describe("existing tag", () => {
    test("no attrs", () => {
      raise("p")
      raise("p", "class")
      raise("p", "data-bar")
      expect(() => { raise("p", "fake")}).toThrow("not allowing p.fake: not in attr whitelist")
      XSSWhitelist.add("p", [])
      raise("p")
      raise("p", "class")
      raise("p", "data-bar")
      expect(() => { raise("p", "fake")}).toThrow("not allowing p.fake: not in attr whitelist")
    })
    test("with no existing addrs", () => {
      raise("b")
      raise("b", "id")
      raise("b", "data-baz")
      expect(() => { raise("b", "bogus")}).toThrow("not allowing b.bogus: not in attr whitelist")
      XSSWhitelist.add("b", ["bogus"])
      raise("b")
      raise("b", "id")
      raise("b", "data-baz")
      raise("b", "bogus")
    })
    test("with existing addrs", () => {
      raise("img")
      raise("img", "src", "https://a.c")
      expect(() => { raise("img", "nope")}).toThrow("not allowing img.nope: not in attr whitelist")
      XSSWhitelist.add("img", ["nope"])
      raise("img")
      raise("img", "src", "https://a.c")
      raise("img", "nope")
    })
  })
})

test("globals", () => {
  expect(XSSWhitelist.allow("i", "fakeglobal")).toStrictEqual(false)
  expect(XSSWhitelist.addGlobalAttr("fakeglobal"))
  expect(XSSWhitelist.allow("i", "fakeglobal")).toStrictEqual(true)
})

test("urls", () => {
  raise("a", "href", "https://a.c")
  raise("a", "href", "#section")
  expect(() => { raise("a", "href", "https:")}).toThrow("not allowing a.href: invalid URL [https:]")
  expect(() => { raise("a", "href", "javascript:alert(1)")}).toThrow("not allowing a.href: invalid protocol javascript:")
  expect(() => { raise("a", "href", "data:alert(1)")}).toThrow("not allowing a.href: invalid protocol data:")
  expect(() => { raise("a", "href", "xyzzy:alert(1)")}).toThrow("not allowing a.href: invalid protocol xyzzy:")
  expect(() => { raise("a", "href", "http://a.c")}).toThrow("not allowing a.href: using unencrypted http")
})

test("srcset", () => {
  raise("img", "srcset", "https://a.c 2x")
  raise("img", "srcset", "https://a.c, https://b.c 2x")
  raise("img", "srcset", "https://a.c 1x, https://b.c 2x")
  expect(() => { raise("img", "srcset")}).toThrow("not allowing img.srcset: no value given for dangerous URL attribute")
  expect(() => { raise("img", "srcset", "javascript:alert(1)")}).toThrow("not allowing img.srcset: invalid protocol javascript:")
  expect(() => { raise("img", "srcset", "https://a.c,javascript:alert(1) 2x")}).toThrow("not allowing img.srcset: invalid protocol javascript:")
})

test("archive", () => {
  XSSWhitelist.add("object", ["archive"])
  XSSWhitelist.add("applet" as never, ["archive"])
  XSSWhitelist.add("div", ["archive"])
  raise("object", "archive", "https://a.c,  https://b.c")
  raise("applet" as never, "archive", "https://a.c  https://b.c")
  raise("div", "archive", "xyzzy")
  expect(() => { raise("object", "archive", "javascript:alert(1)")}).toThrow("not allowing object.archive: invalid protocol javascript:")
  expect(() => { raise("object", "archive", "https://a.c,javascript:alert(1)")}).toThrow("not allowing object.archive: invalid protocol javascript:")
  expect(() => { raise("object", "archive")}).toThrow("not allowing object.archive: no value given for dangerous URL attribute")
  expect(() => { raise("applet" as never, "archive", "javascript:alert(1)")}).toThrow("not allowing applet.archive: invalid protocol javascript:")
  expect(() => { raise("applet" as never, "archive", "https://a.c javascript:alert(1)")}).toThrow("not allowing applet.archive: invalid protocol javascript:")
  expect(() => { raise("applet" as never, "archive")}).toThrow("not allowing applet.archive: no value given for dangerous URL attribute")
})

test("meta content refresh", () => {
  XSSWhitelist.add("meta", ["content"])
  raise("meta", "content", "1000")
  raise("meta", "content", "1000; url=https://a.c")
  expect(() => { raise("meta", "content", "1000; url=javascript:alert(1)")}).toThrow("not allowing meta.content: invalid protocol javascript:")
  expect(() => { raise("meta", "content")}).toThrow("not allowing meta.content: no value given for dangerous URL attribute")
  XSSWhitelist.add("div", ["content"])
  raise("div", "content", "xyzzy")
})

test("addHandler", () => {
  XSSWhitelist.addHandler("data-foo", (tag:string, attr:string, value?:string) => {
    throw new XSSWhitelistError(tag, attr, "bad value: " + value)
  })
  expect(() => { raise("div", "data-foo", "x")}).toThrow("not allowing div.data-foo: bad value: x")
})

test("addProtocol", () => {
  expect(() => { raise("a", "href", "sftp://x")}).toThrow("not allowing a.href: invalid protocol sftp:")
  expect(() => { raise("a", "href", "foo://x")}).toThrow("not allowing a.href: invalid protocol foo:")
  XSSWhitelist.addProtocol("sftp")
  XSSWhitelist.addProtocol("foo:")
  raise("a", "href", "sftp://x")
  raise("a", "href", "foo://x")
  expect(() => {XSSWhitelist.addProtocol("")}).toThrow("protocol is required")
})
