export class XSSWhitelistError extends Error {
  constructor(tag:string, attr:string|undefined, message:string, options?:ErrorOptions) {
    super(attr ? "not allowing " + tag + "." + attr + ": " + message : "not allowing tag " + tag + ": " + message, options)
  }
}

export namespace XSSWhitelist {//

type Whitelist = Record<string,Set<string>|null>

const globals = new Set([
"accesskey",
"autocapitalize",
"autofocus",
"class",
"contenteditable",
"dir",
"draggable",
"enterkeyhint",
"hidden",
"id",
"inert",
"inputmode",
"lang",
"nonce",
"part",
"role",
"slot",
"spellcheck",
"tabindex",
"translate",
])

const protocols = new Set(["https:"])

const urlProblem = "no value given for dangerous URL attribute"

export const urlHandler = (tag:string, attr:string, value?:string):void => {
  if (value === undefined) {
    throw new XSSWhitelistError(tag, attr, urlProblem)
  }
  let url:URL
  try {
    url = new URL(value, window.location.href)
  } catch (e) {
    throw new XSSWhitelistError(tag, attr, "invalid URL [" + value + "]", {cause:e})
  }
  if (protocols.has(url.protocol)) return
  if (url.protocol === "http:") {
    if (url.hostname === "localhost") return
    throw new XSSWhitelistError(tag, attr, "using unencrypted http")
  } else {
    throw new XSSWhitelistError(tag, attr, "invalid protocol " + url.protocol)
  }
}

const handlers = new Map<string,(tag:string,attr:string,value?:string)=>void>()

for (const attr of [
"action",
"archive",
"background",
"cite",
"codebase",
"classid",
"data",
"dynsrc",
"formaction",
"href",
"longdesc",
"lowsrc",
"poster",
"profile",
"src",
"usemap",
]) {
  handlers.set(attr, urlHandler)
}

handlers.set("content", (tag:string, attr:string, value?:string) => {
  if (tag !== "meta") return
  if (value === undefined) throw new XSSWhitelistError(tag, attr, urlProblem)
  const parts = value.split("url=")
  if (parts.length < 2) return
  urlHandler(tag, attr, parts[1])
})

handlers.set("srcset", (tag:string, attr:string, value?:string) => {
  if (value === undefined) throw new XSSWhitelistError(tag, attr, urlProblem)
  const pairs = value.trim().split(",")
  for (const pair of pairs) {
    const parts = pair.trim().split(" ")
    urlHandler(tag, attr, parts[0])
  }
})

handlers.set("archive", (tag:string, attr:string, value?:string) => {
  let sep:string|undefined = undefined
  if (tag === "object") sep = ","
  if (tag === "applet") sep = " "
  if (sep === undefined) return
  if (value === undefined) throw new XSSWhitelistError(tag, attr, urlProblem)
  const urls = value.split(sep)
  for (const url of urls) {
    if (url !== "") {
      urlHandler(tag, attr, url)
    }
  }
})

const list:Whitelist = {
  a: new Set(["href", "target", "title"]),
  abbr: new Set(["title"]),
  address: null,
  area: new Set(["alt", "coords", "href", "shape"]),
  article: null,
  aside: null,
  audio: new Set([
    "autoplay",
    "controls",
    "crossorigin",
    "loop",
    "muted",
    "preload",
    "src",
  ]),
  b: null,
  body: null,
  bdi: new Set(["dir"]),
  bdo: new Set(["dir"]),
  blockquote: new Set(["cite"]),
  br: null,
  button: new Set(["disabled","popovertarget","popovertargetaction"]),
  caption: null,
  cite: null,
  code: null,
  col: new Set(["align","span","valign","width"]),
  colgroup: new Set(["align","span","valign","width"]),
  data: new Set(["value"]),
  datalist: null,
  dd: null,
  del: new Set(["cite","datetime"]),
  details: new Set(["name","open"]),
  dfn: new Set(["title"]),
  div: null,
  dl: null,
  dt: null,
  em: null,
  fieldset: new Set(["disabled","form","name"]),
  figcaption: null,
  figure: null,
  footer: null,
  form: null,
  h1: null,
  h2: null,
  h3: null,
  h4: null,
  h5: null,
  h6: null,
  header: null,
  hr: null,
  i: null,
  img: new Set([ "alt","height","loading","src","srcset","title","width"]),
  input: new Set([
    "accept",
    "alt",
    "autocomplete",
    "capture",
    "checked",
    "dirname",
    "disabled",
    "height",
    "list",
    "max",
    "maxlength",
    "min",
    "minlength",
    "multiple",
    "name",
    "pattern",
    "placeholder",
    "readonly",
    "required",
    "size",
    "src",
    "step",
    "type",
    "value",
    "width",
  ]),
  ins: new Set(["cite","datetime"]),
  kbd: null,
  label: new Set(["for"]),
  legend: null,
  li: new Set(["value"]),
  main: null,
  mark: null,
  meter: new Set(["high","low","max","min","optimum","value"]),
  nav: null,
  ol: new Set(["reveresed","start","type"]),
  option: new Set(["disabled","label","selected","value"]),
  optiongrp: new Set(["disabled","label"]),
  p: null,
  picture: null,
  pre: null,
  progress: new Set(["max","value"]),
  q: new Set(["cite"]),
  rp: null,
  rt: null,
  ruby: null,
  s: null,
  samp: null,
  search: null,
  section: null,
  select: new Set([
    "autocomplete",
    "disabled",
    "multiple",
    "name",
    "required",
    "size",
  ]),
  small: null,
  source: new Set(["height","media","src","srcset","sizes","type","width"]),
  span: null,
  sub: null,
  summary: null,
  sup: null,
  strong: null,
  table: new Set([ "align","border","valign","width"]),
  tbody: new Set(["align","valign"]),
  td: new Set(["align","colspan","rowspan","valign","width"]),
  textarea: new Set([
    "autocomplete",
    "autocorrect",
    "cols",
    "dirname",
    "disabled",
    "maxlength",
    "minlength",
    "placeholder",
    "readonly",
    "required",
    "rows",
    "spellcheck",
    "wrap",
  ]),
  tfoot: new Set(["align","valign"]),
  th: new Set(["align","colspan","rowspan","valign","width"]),
  thead: new Set(["align","valign"]),
  time: new Set(["datetime"]),
  tr: new Set(["align","rowspan","valign"]),
  track: new Set(["default","kind","label","src"]),
  u: null,
  ul: null,
  var: null,
  video: new Set([
    "autoplay",
    "controls",
    "crossorigin",
    "loop",
    "muted",
    "playsinline",
    "poster",
    "preload",
    "src",
    "height",
    "width",
  ]),
  wbr: null,
}

export const allow = (tag:keyof HTMLElementTagNameMap, attr?:string, value?:string):boolean => {
  try {
    raise(tag, attr, value)
    return true
  } catch (e:any) {
    console.error(e)
    return false
  }
}

export const raise = (tag:keyof HTMLElementTagNameMap, attr?:string, value?:string):void => {
  if (!(tag in list)) throw new XSSWhitelistError(tag, attr, "not in tag whitelist")
  if (attr === undefined) return
  handlers.get(attr)?.(tag, attr, value)
  if (globals.has(attr) || attr.startsWith("data-") || attr.startsWith("aria-")) return
  if (list[tag]?.has(attr) ?? false) return
  throw new XSSWhitelistError(tag, attr, "not in attr whitelist")
}

export const add = (tag:keyof HTMLElementTagNameMap, attrs: string[]):void => {
  if (tag in list) {
    if (attrs.length > 0) {
      if (list[tag] === null) list[tag] = new Set(attrs)
      else attrs.forEach(x => list[tag]!.add(x))
    } 
  } else if (attrs.length > 0) {
    list[tag] = new Set(attrs)
  } else {
    list[tag] = null
  }
}

export const addGlobalAttr = (attr:string):void => {
  globals.add(attr)
}

export const addHandler = (attr:string, handler:(tag:string, attr:string, value?:string)=>void):void => {
  handlers.set(attr, handler)
}

export const addProtocol = (protocol:string):void => {
  if (protocol === "") throw new TypeError("protocol is required")
  if (!protocol.endsWith(":")) protocol += ":"
  protocols.add(protocol)
}

}//