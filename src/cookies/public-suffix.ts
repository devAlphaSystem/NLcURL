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

const PSL_CACHE_MAX = 512;
const pslCache = new Map<string, number>();

function findEffectiveTLDLengthCached(domain: string): number {
  const cached = pslCache.get(domain);
  if (cached !== undefined) return cached;
  const result = findEffectiveTLDLength(domain);
  if (pslCache.size >= PSL_CACHE_MAX) {
    const firstKey = pslCache.keys().next().value;
    if (firstKey !== undefined) pslCache.delete(firstKey);
  }
  pslCache.set(domain, result);
  return result;
}

/**
 * Determines whether a domain is a public suffix (eTLD) according to the Mozilla Public Suffix List.
 *
 * @param {string} domain - The domain to check.
 * @returns {boolean} `true` if the domain is a public suffix.
 */
export function isPublicSuffix(domain: string): boolean {
  const d = domain.toLowerCase();
  const labels = d.split(".");
  return labels.length === findEffectiveTLDLengthCached(d);
}

/**
 * Extracts the registrable domain (eTLD+1) from a hostname using the Public Suffix List.
 *
 * @param {string} hostname - The full hostname.
 * @returns {string|null} The registrable domain, or `null` if the hostname is itself a public suffix.
 */
export function getRegistrableDomain(hostname: string): string | null {
  const domain = hostname.toLowerCase();
  const labels = domain.split(".");

  if (labels.length < 2) return null;

  const etldLength = findEffectiveTLDLengthCached(domain);

  if (labels.length <= etldLength) {
    return null;
  }

  return labels.slice(labels.length - etldLength - 1).join(".");
}
