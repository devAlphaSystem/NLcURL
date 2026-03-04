import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../../src/cli/args.js";

describe("parseArgs", () => {
  it("parses a simple URL", () => {
    const result = parseArgs(["node", "nlcurl", "https://example.com"]);
    assert.equal(result.url, "https://example.com");
    assert.equal(result.method, "GET");
  });

  it("parses -X method flag", () => {
    const result = parseArgs(["node", "nlcurl", "-X", "POST", "https://example.com"]);
    assert.equal(result.method, "POST");
  });

  it("parses --request method flag", () => {
    const result = parseArgs(["node", "nlcurl", "--request", "PUT", "https://example.com"]);
    assert.equal(result.method, "PUT");
  });

  it("parses -H header flag", () => {
    const result = parseArgs(["node", "nlcurl", "-H", "Content-Type: application/json", "https://example.com"]);
    assert.deepEqual(result.headers, [["Content-Type", "application/json"]]);
  });

  it("parses multiple headers", () => {
    const result = parseArgs(["node", "nlcurl", "-H", "Authorization: Bearer token", "-H", "Accept: text/html", "https://example.com"]);
    assert.equal(result.headers.length, 2);
  });

  it("parses -d data flag", () => {
    const result = parseArgs(["node", "nlcurl", "-d", "key=value", "https://example.com"]);
    assert.equal(result.data, "key=value");
    assert.equal(result.method, "POST");
  });

  it("parses --data-raw flag", () => {
    const result = parseArgs(["node", "nlcurl", "--data-raw", '{"json":true}', "https://example.com"]);
    assert.equal(result.dataRaw, '{"json":true}');
    assert.equal(result.method, "POST");
  });

  it("parses -k insecure flag", () => {
    const result = parseArgs(["node", "nlcurl", "-k", "https://example.com"]);
    assert.equal(result.insecure, true);
  });

  it("parses -L follow redirects flag", () => {
    const result = parseArgs(["node", "nlcurl", "-L", "https://example.com"]);
    assert.equal(result.followRedirects, true);
  });

  it("parses --no-location disables redirect following", () => {
    const result = parseArgs(["node", "nlcurl", "--no-location", "https://example.com"]);
    assert.equal(result.followRedirects, false);
  });

  it("parses --max-redirs flag", () => {
    const result = parseArgs(["node", "nlcurl", "--max-redirs", "5", "https://example.com"]);
    assert.equal(result.maxRedirects, 5);
  });

  it("parses -m timeout flag (in seconds to ms)", () => {
    const result = parseArgs(["node", "nlcurl", "-m", "10", "https://example.com"]);
    assert.equal(result.timeout, 10000);
  });

  it("parses --max-time with decimal", () => {
    const result = parseArgs(["node", "nlcurl", "--max-time", "2.5", "https://example.com"]);
    assert.equal(result.timeout, 2500);
  });

  it("parses --http1.1 flag", () => {
    const result = parseArgs(["node", "nlcurl", "--http1.1", "https://example.com"]);
    assert.equal(result.httpVersion, "1.1");
  });

  it("parses --http2 flag", () => {
    const result = parseArgs(["node", "nlcurl", "--http2", "https://example.com"]);
    assert.equal(result.httpVersion, "2");
  });

  it("parses --impersonate flag", () => {
    const result = parseArgs(["node", "nlcurl", "--impersonate", "chrome_131", "https://example.com"]);
    assert.equal(result.impersonate, "chrome_131");
  });

  it("parses --flag=value syntax", () => {
    const result = parseArgs(["node", "nlcurl", "--impersonate=firefox_133", "https://example.com"]);
    assert.equal(result.impersonate, "firefox_133");
  });

  it("parses boolean flags", () => {
    const result = parseArgs(["node", "nlcurl", "-v", "-s", "--compressed", "-I", "-i", "--stealth", "https://example.com"]);
    assert.equal(result.verbose, true);
    assert.equal(result.silent, true);
    assert.equal(result.compressed, true);
    assert.equal(result.head, true);
    assert.equal(result.method, "HEAD");
    assert.equal(result.include, true);
    assert.equal(result.stealth, true);
  });

  it("parses --help flag", () => {
    const result = parseArgs(["node", "nlcurl", "--help"]);
    assert.equal(result.help, true);
  });

  it("parses --version flag", () => {
    const result = parseArgs(["node", "nlcurl", "-V"]);
    assert.equal(result.version, true);
  });

  it("parses proxy flags", () => {
    const result = parseArgs(["node", "nlcurl", "-x", "http://proxy.local:8080", "-U", "user:pass", "https://example.com"]);
    assert.equal(result.proxy, "http://proxy.local:8080");
    assert.equal(result.proxyAuth, "user:pass");
  });

  it("parses cookie flags", () => {
    const result = parseArgs(["node", "nlcurl", "-b", "session=abc", "-c", "/tmp/cookies.txt", "https://example.com"]);
    assert.equal(result.cookies, "session=abc");
    assert.equal(result.cookieJar, "/tmp/cookies.txt");
  });

  it("throws on flag requiring value without one", () => {
    assert.throws(() => {
      parseArgs(["node", "nlcurl", "-X"]);
    });
  });

  it("defaults are set correctly", () => {
    const result = parseArgs(["node", "nlcurl", "https://example.com"]);
    assert.equal(result.followRedirects, true);
    assert.equal(result.maxRedirects, 20);
    assert.equal(result.timeout, 30000);
    assert.equal(result.insecure, false);
    assert.equal(result.verbose, false);
    assert.equal(result.stealth, false);
  });
});
