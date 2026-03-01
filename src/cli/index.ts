#!/usr/bin/env node
/**
 * NLcURL CLI entry point.
 *
 * Usage: nlcurl [OPTIONS] <URL>
 */

import * as fs from 'node:fs';
import * as process from 'node:process';
import { parseArgs } from './args.js';
import { formatOutput, formatVerboseRequest, printHelp } from './output.js';
import { request } from '../core/client.js';
import { listProfiles } from '../fingerprints/database.js';
import type { NLcURLRequest, HttpMethod } from '../core/request.js';

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  // ---- Meta commands ----

  if (args.help) {
    process.stdout.write(printHelp() + '\n');
    return;
  }

  if (args.version) {
    const pkg = JSON.parse(
      fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
    );
    process.stdout.write(`nlcurl ${pkg.version}\n`);
    return;
  }

  if (args.listProfiles) {
    const profiles = listProfiles();
    for (const name of profiles) {
      process.stdout.write(name + '\n');
    }
    return;
  }

  // ---- Validate URL ----

  if (!args.url) {
    process.stderr.write('Error: No URL specified. Use --help for usage.\n');
    process.exit(1);
  }

  // Prepend https:// if no scheme is given
  let url = args.url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  // ---- Build request ----

  const headers: Record<string, string> = {};
  for (const [key, value] of args.headers) {
    headers[key] = value;
  }

  if (args.userAgent) {
    headers['user-agent'] = args.userAgent;
  }

  if (args.compressed && !headers['accept-encoding']) {
    headers['accept-encoding'] = 'gzip, deflate, br';
  }

  if (args.cookies) {
    headers['cookie'] = args.cookies;
  }

  const body = args.data ?? args.dataRaw ?? undefined;

  const req: NLcURLRequest = {
    url,
    method: args.method as HttpMethod,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body,
    impersonate: args.impersonate ?? undefined,
    ja3: args.ja3 ?? undefined,
    akamai: args.akamai ?? undefined,
    stealth: args.stealth || undefined,
    proxy: args.proxy ?? undefined,
    insecure: args.insecure || undefined,
    followRedirects: args.followRedirects,
    maxRedirects: args.maxRedirects,
    timeout: args.timeout,
    httpVersion: (args.httpVersion as '1.1' | '2') ?? undefined,
  };

  if (args.proxyAuth) {
    const [user, pass] = args.proxyAuth.split(':');
    if (user && pass) {
      req.proxyAuth = [user, pass];
    }
  }

  // ---- Verbose request output ----

  if (args.verbose) {
    const verboseReq = formatVerboseRequest(
      req.method ?? 'GET',
      url,
      headers,
    );
    process.stderr.write(verboseReq + '\n');
  }

  // ---- Execute request ----

  try {
    const response = await request(req);
    const output = formatOutput(response, args);

    if (args.output) {
      fs.writeFileSync(args.output, response.rawBody);
      if (!args.silent) {
        process.stderr.write(`Written to ${args.output}\n`);
      }
    } else {
      process.stdout.write(output);
      // Add trailing newline if body doesn't end with one
      if (output.length > 0 && !output.endsWith('\n')) {
        process.stdout.write('\n');
      }
    }

    if (!response.ok && !args.silent) {
      process.exit(22);
    }
  } catch (err) {
    if (!args.silent) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`nlcurl: ${message}\n`);
    }
    process.exit(1);
  }
}

main();
