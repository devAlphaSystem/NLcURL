/**
 * Public Suffix List (PSL) implementation for cookie domain validation.
 * Uses the complete Mozilla Public Suffix List (10,000+ rules) to prevent
 * supercookie attacks across all registered TLDs, ccSLDs, and hosting platforms.
 *
 * The data is auto-generated from https://publicsuffix.org/list/public_suffix_list.dat
 * via `npx tsx scripts/update-psl.ts`. Regenerate periodically to stay current.
 *
 * Rules follow the PSL algorithm (https://wiki.mozilla.org/Public_Suffix_List/Algorithm):
 *   - A plain entry (e.g. `com`) means that label is a public suffix.
 *   - A wildcard entry (e.g. `*.uk`) means all two-label domains under `.uk` are suffixes.
 *   - An exception entry (e.g. `!www.ck`) overrides a wildcard and is NOT a suffix.
 */

import { PSL_RULES } from "./psl-data.js";

interface PSLRule {
  labels: string[];
  isException: boolean;
  isWildcard: boolean;
}

function parseRule(raw: string): PSLRule {
  const isException = raw.startsWith("!");
  const cleaned = isException ? raw.slice(1) : raw;
  const isWildcard = cleaned.startsWith("*.");
  const effective = isWildcard ? cleaned.slice(2) : cleaned;
  const labels = effective.split(".").reverse();
  return { labels, isException, isWildcard };
}

const RULES: PSLRule[] = PSL_RULES.map(parseRule);

interface TrieNode {
  children: Map<string, TrieNode>;
  isPublicSuffix: boolean;
  hasWildcard: boolean;
  exceptions: Set<string>;
}

function createNode(): TrieNode {
  return {
    children: new Map(),
    isPublicSuffix: false,
    hasWildcard: false,
    exceptions: new Set(),
  };
}

const ROOT: TrieNode = createNode();

for (const rule of RULES) {
  if (rule.isException) {
    let node = ROOT;
    for (let i = 0; i < rule.labels.length - 1; i++) {
      const label = rule.labels[i]!;
      if (!node.children.has(label)) {
        node.children.set(label, createNode());
      }
      node = node.children.get(label)!;
    }
    node.exceptions.add(rule.labels[rule.labels.length - 1]!);
    continue;
  }

  let node = ROOT;
  for (const label of rule.labels) {
    if (!node.children.has(label)) {
      node.children.set(label, createNode());
    }
    node = node.children.get(label)!;
  }
  if (rule.isWildcard) {
    node.hasWildcard = true;
  } else {
    node.isPublicSuffix = true;
  }
}

/**
 * Finds the number of labels in the effective TLD for a given domain,
 * following the Mozilla PSL algorithm:
 *   1. Walk the trie from right to left, tracking the longest matching rule.
 *   2. Wildcards extend the eTLD by one label; exceptions retract it.
 *   3. Default rule: if no rule matches, treat the rightmost label as the eTLD.
 *
 * @param {string} domain - Lowercase domain with labels separated by '.'.
 * @returns {number} Number of labels (from the right) forming the eTLD.
 */
function findEffectiveTLDLength(domain: string): number {
  const labels = domain.split(".").reverse();
  let node = ROOT;
  let etldLabels = 1;

  for (let i = 0; i < labels.length; i++) {
    const label = labels[i]!;
    const child = node.children.get(label);

    if (child) {
      node = child;

      if (node.isPublicSuffix) {
        etldLabels = i + 1;
      }

      if (node.hasWildcard && i + 1 < labels.length) {
        const nextLabel = labels[i + 1]!;
        if (node.exceptions.has(nextLabel)) {
          etldLabels = i + 1;
        } else {
          etldLabels = i + 2;
        }
      }
    } else {
      if (node.hasWildcard) {
        if (!node.exceptions.has(label)) {
          etldLabels = i + 1;
        }
      }
      break;
    }
  }

  return etldLabels;
}

/**
 * Determines whether the given domain is a public suffix (effective TLD).
 * A public suffix is a domain under which the general public can register
 * names — e.g. `com`, `co.uk`, `github.io`.
 *
 * Cookies must never be set with a `domain` attribute equal to a public
 * suffix, as that would create a supercookie affecting all sites under
 * that suffix.
 *
 * @param {string} domain - The domain to check (lowercase, no trailing dot).
 * @returns {boolean} `true` if the domain is a public suffix.
 */
export function isPublicSuffix(domain: string): boolean {
  const d = domain.toLowerCase();
  const labels = d.split(".");
  return labels.length === findEffectiveTLDLength(d);
}

/**
 * Returns the registrable domain (eTLD+1) for the given hostname.
 * For example, `"www.example.co.uk"` → `"example.co.uk"`.
 * Returns `null` if the domain is itself a public suffix or if
 * the input is invalid.
 *
 * @param {string} hostname - Full hostname (no trailing dot).
 * @returns {string | null} The registrable domain, or `null`.
 */
export function getRegistrableDomain(hostname: string): string | null {
  const domain = hostname.toLowerCase();
  const labels = domain.split(".");

  if (labels.length < 2) return null;

  const etldLength = findEffectiveTLDLength(domain);

  if (labels.length <= etldLength) {
    return null;
  }

  return labels.slice(labels.length - etldLength - 1).join(".");
}
