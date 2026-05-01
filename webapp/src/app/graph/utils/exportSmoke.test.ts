/**
 * End-to-end smoke tests for every export format on every page table.
 *
 * Validates:
 *   - No exceptions on representative sample data
 *   - Filename slugs and timestamp suffix are correct
 *   - Output payloads (CSV, JSON, MD) are well-formed
 *
 * Browser DOM bits (URL.createObjectURL, anchor click) are intercepted so we
 * can read the emitted Blob content back.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

import {
  exportToCsv,
  exportToJson,
  exportToMarkdown,
} from './exportCsv'
import {
  exportRedZoneCsv,
  exportRedZoneJson,
  exportRedZoneMarkdown,
} from '../components/RedZoneTables/exportCsv'
import {
  exportJsReconCsv,
  exportJsReconJson,
  exportJsReconMarkdown,
  type JsReconData,
} from '../components/JsReconTable/JsReconTable'
import type { TableRow } from '../hooks/useTableData'

// ============================================================
// DOM interception helpers
// ============================================================

interface CapturedDownload {
  filename: string
  text: string
  mimeType: string
}

let downloads: CapturedDownload[] = []
let originalCreateObjectURL: typeof URL.createObjectURL
let originalRevokeObjectURL: typeof URL.revokeObjectURL

async function flush() {
  // anchor.click is async (await blob.text()) -- give microtasks one tick
  await Promise.resolve()
  await Promise.resolve()
}

beforeEach(() => {
  downloads = []

  const blobs = new Map<string, Blob>()
  originalCreateObjectURL = URL.createObjectURL
  originalRevokeObjectURL = URL.revokeObjectURL
  let counter = 0
  URL.createObjectURL = vi.fn((blob: Blob) => {
    const url = `blob:test/${++counter}`
    blobs.set(url, blob)
    return url
  })
  URL.revokeObjectURL = vi.fn()

  const originalCreate = document.createElement.bind(document)
  vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
    const el = originalCreate(tag)
    if (tag.toLowerCase() === 'a') {
      const a = el as HTMLAnchorElement
      a.click = async () => {
        const blob = blobs.get(a.href)
        if (blob) {
          const text = await blob.text()
          downloads.push({ filename: a.download, text, mimeType: blob.type })
        }
      }
    }
    return el
  }) as typeof document.createElement)
})

afterEach(() => {
  URL.createObjectURL = originalCreateObjectURL
  URL.revokeObjectURL = originalRevokeObjectURL
  vi.restoreAllMocks()
})

const TS_SUFFIX_RE = /-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.(csv|json|md)$/

// ============================================================
// Tiny CSV parser (handles RFC 4180 quoting) -- avoids pulling
// in a full dep just for the smoke check.
// ============================================================

function parseCsv(text: string): string[][] {
  const stripped = text.replace(/^\uFEFF/, '')
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQuotes = false
  for (let i = 0; i < stripped.length; i++) {
    const ch = stripped[i]
    if (inQuotes) {
      if (ch === '"') {
        if (stripped[i + 1] === '"') { cell += '"'; i++ } else { inQuotes = false }
      } else {
        cell += ch
      }
    } else {
      if (ch === '"') inQuotes = true
      else if (ch === ',') { row.push(cell); cell = '' }
      else if (ch === '\r') { /* skip */ }
      else if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = '' }
      else cell += ch
    }
  }
  if (cell.length || row.length) { row.push(cell); rows.push(row) }
  return rows
}

// ============================================================
// Sample fixtures
// ============================================================

function makeTableRows(): TableRow[] {
  return [
    {
      node: {
        id: 'sub-1',
        type: 'Subdomain',
        name: 'admin.example.com',
        properties: {
          subdomain: 'admin.example.com',
          tags: ['live', 'auth'],
          banner: 'HTTP/1.1 200 OK\u0000\u0007 evil-binary',
          response_size: 12345,
          is_alive: true,
          long_text: 'X'.repeat(40000),
          project_id: 'should-be-skipped',
          user_id: 'should-be-skipped',
        },
      } as any,
      connectionsIn: [
        { nodeId: 'd-1', nodeName: 'example.com', nodeType: 'Domain', relationType: 'PART_OF' },
      ],
      connectionsOut: [
        { nodeId: 'ep-1', nodeName: '/login', nodeType: 'Endpoint', relationType: 'HAS_ENDPOINT' },
      ],
      getLevel2: () => [
        { nodeId: 'tld-1', nodeName: 'example', nodeType: 'TLD', relationType: '2 hops' },
      ],
      getLevel3: () => [],
    },
    {
      node: {
        id: 'ep-1',
        type: 'Endpoint',
        name: '/login',
        properties: { method: 'POST', path: '/login', is_alive: false },
      } as any,
      connectionsIn: [],
      connectionsOut: [],
      getLevel2: () => [],
      getLevel3: () => [],
    },
  ]
}

function makeRedZoneRows() {
  return [
    {
      severity: 'critical',
      hostname: 'admin.example.com',
      port: 443,
      isCdn: true,
      tags: ['production', 'auth'],
      cveCount: 12,
      lastSeen: null,
      payload: { method: 'GET', path: '/admin' },
      garbled: 'header\u0000binary\u0007junk',
    },
    {
      severity: 'low',
      hostname: 'cdn.example.com',
      port: 80,
      isCdn: false,
      tags: [],
      cveCount: 0,
      lastSeen: '2026-04-29',
      payload: null,
      garbled: 'normal text',
    },
  ]
}

const RED_ZONE_COLUMNS = [
  { key: 'severity', header: 'Severity' },
  { key: 'hostname', header: 'Hostname' },
  { key: 'port', header: 'Port' },
  { key: 'isCdn', header: 'CDN' },
  { key: 'tags', header: 'Tags' },
  { key: 'cveCount', header: 'CVEs' },
  { key: 'lastSeen', header: 'Last Seen' },
  { key: 'payload', header: 'Payload' },
  { key: 'garbled', header: 'Garbled' },
]

function makeJsReconData(): JsReconData {
  return {
    scan_metadata: { js_files_analyzed: 3 },
    secrets: [
      {
        severity: 'critical',
        name: 'AWS Access Key',
        redacted_value: 'AKIA…X',
        matched_text: 'AKIAFAKE\u0001binary',
        category: 'cloud',
        source_url: 'https://example.com/app.js',
        line_number: 42,
        context: 'var k = "AKIA…X"',
        detection_method: 'regex',
        validation: { status: 'validated' },
        confidence: 'high',
        validator_ref: 'aws',
      },
    ],
    endpoints: [
      {
        severity: 'info',
        method: 'POST',
        path: '/api/v1/users',
        full_url: 'https://api.example.com/api/v1/users',
        type: 'rest',
        category: 'user',
        base_url: 'https://api.example.com',
        source_js: 'https://example.com/app.js',
        parameters: ['id', 'name'],
        line_number: 156,
      },
    ],
    discovered_subdomains: ['admin.example.com', 'api.example.com'],
    external_domains: [{ domain: 'cdn.example.net', times_seen: 5 }],
  }
}

// ============================================================
// All-Nodes (page-level)
// ============================================================

describe('All-Nodes table exports', () => {
  test('CSV: produces a parseable file, sanitizes binary chars, skips internal fields', async () => {
    const rows = makeTableRows()
    exportToCsv(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)
    expect(dl.mimeType).toBe('text/csv;charset=utf-8')

    const grid = parseCsv(dl.text)
    const headers = grid[0]
    expect(headers).toContain('Type')
    expect(headers).toContain('Name')
    // Internal fields are filtered out at row-build time
    expect(headers).not.toContain('project_id')
    expect(headers).not.toContain('user_id')

    // Row 1 = first node = admin.example.com
    const dataRows = grid.slice(1).filter(r => r.length > 1)
    expect(dataRows).toHaveLength(2)
    const nameIdx = headers.indexOf('Name')
    const typeIdx = headers.indexOf('Type')
    expect(dataRows[0][typeIdx]).toBe('Subdomain')
    expect(dataRows[0][nameIdx]).toBe('admin.example.com')

    // banner had \u0000 and \u0007 -- must be stripped
    const bannerIdx = headers.indexOf('banner')
    expect(dataRows[0][bannerIdx]).not.toMatch(/[\u0000\u0007]/)
    // Long text passed through (CSV has no XLSX-style 32767 cap)
    const longIdx = headers.indexOf('long_text')
    expect(dataRows[0][longIdx].length).toBe(40000)
  })

  test('JSON: produces parseable JSON with all expected fields', async () => {
    const rows = makeTableRows()
    exportToJson(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Type).toBe('Subdomain')
    expect(data[0].Name).toBe('admin.example.com')
    expect(data[0]['Connections In']).toBe(1)
  })

  test('Markdown: produces a valid GFM table', async () => {
    const rows = makeTableRows()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redamon-data-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# Nodes Export')
    expect(md).toContain('| Type |')
    expect(md).toMatch(/\| --- \|/)
    expect(md).toContain('admin.example.com')
    expect(md).toContain('Subdomain')
    const lines = md.split('\n')
    const dataLines = lines.filter(l => l.startsWith('| ') && !l.includes(' --- '))
    const pipeCounts = dataLines.map(l => (l.match(/\|/g) || []).length)
    expect(new Set(pipeCounts).size).toBe(1)
  })
})

// ============================================================
// Red Zone tables (e.g. Blast Radius / Secrets / etc.)
// ============================================================

describe('Red Zone table exports', () => {
  test('CSV: produces a parseable file with the configured headers', async () => {
    exportRedZoneCsv(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)

    const grid = parseCsv(dl.text)
    expect(grid[0]).toEqual([
      'Severity', 'Hostname', 'Port', 'CDN', 'Tags', 'CVEs', 'Last Seen', 'Payload', 'Garbled',
    ])
    const data = grid.slice(1).filter(r => r.length > 1)
    expect(data).toHaveLength(2)
    expect(data[0][0]).toBe('critical')
    expect(data[0][1]).toBe('admin.example.com')
    expect(data[0][2]).toBe('443')
    expect(data[0][3]).toBe('true')
    // Arrays joined
    expect(data[0][4]).toBe('production, auth')
    // Object stringified
    expect(data[0][7]).toContain('"method":"GET"')
    // Binary chars stripped
    expect(data[0][8]).not.toMatch(/[\u0000\u0007]/)
    // Null cell empty
    expect(data[0][6]).toBe('')
  })

  test('JSON: produces parseable JSON, keeps native objects/arrays', async () => {
    exportRedZoneJson(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data)).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[0].Severity).toBe('critical')
    expect(typeof data[0].Port).toBe('number')
    expect(typeof data[0].CDN).toBe('boolean')
    expect(Array.isArray(data[0].Tags)).toBe(true)
    expect(data[0].Payload.method).toBe('GET')
    expect(data[0]['Last Seen']).toBeNull()
  })

  test('Markdown: produces a GFM table with proper escaping', async () => {
    exportRedZoneMarkdown(makeRedZoneRows(), 'Blast-Radius', RED_ZONE_COLUMNS, 'redzone-blast-radius')
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^redzone-blast-radius-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# Blast-Radius')
    expect(md).toMatch(/\| Severity \| Hostname \|/)
    expect(md).toContain('admin.example.com')
    expect(md).toContain('production, auth')
  })
})

// ============================================================
// JS Recon (multi-section)
// ============================================================

describe('JS Recon table exports', () => {
  test('CSV: writes one section per non-empty bucket separated by section markers', async () => {
    exportJsReconCsv(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename).toMatch(TS_SUFFIX_RE)

    const text = dl.text
    expect(text).toContain('# Section: Secrets')
    expect(text).toContain('# Section: Endpoints')
    expect(text).toContain('# Section: Subdomains')
    expect(text).toContain('# Section: External Domains')
    // Sections that are empty (e.g. dependencies, source maps) must be absent
    expect(text).not.toContain('# Section: Dependencies')
    expect(text).not.toContain('# Section: Source Maps')

    // Drill into the Secrets section: the row after its header should contain the secret name
    expect(text).toContain('AWS Access Key')
    // \u0001 in matched_text must be stripped
    expect(text).not.toMatch(/[\u0000-\u0008]/)
  })

  test('JSON: produces a parseable object keyed by section name', async () => {
    exportJsReconJson(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.json')).toBe(true)
    const data = JSON.parse(dl.text)
    expect(Array.isArray(data['Secrets'])).toBe(true)
    expect(data['Secrets']).toHaveLength(1)
    expect(data['Secrets'][0].name).toBe('AWS Access Key')
    expect(data['Secrets'][0]['validation.status']).toBe('validated')
    expect(data['Dependencies']).toBeUndefined()
    expect(data['Source Maps']).toBeUndefined()
    expect(data['Subdomains']).toEqual([
      { subdomain: 'admin.example.com' },
      { subdomain: 'api.example.com' },
    ])
  })

  test('Markdown: produces a multi-section markdown doc', async () => {
    exportJsReconMarkdown(makeJsReconData())
    await flush()
    expect(downloads).toHaveLength(1)
    const dl = downloads[0]
    expect(dl.filename).toMatch(/^js-recon-/)
    expect(dl.filename.endsWith('.md')).toBe(true)
    const md = dl.text
    expect(md).toContain('# JS Recon Findings')
    expect(md).toContain('## Secrets (1)')
    expect(md).toContain('## Endpoints (1)')
    expect(md).toContain('## Subdomains (2)')
    expect(md).toContain('## External Domains (1)')
    expect(md).not.toContain('## Dependencies')
    expect(md).not.toContain('## Source Maps')
    expect(md).toContain('AWS Access Key')
  })
})

// ============================================================
// Sequential exports
// ============================================================

describe('Multiple sequential exports', () => {
  test('Each call produces an independent download with the right extension', async () => {
    const rows = makeTableRows()
    exportToCsv(rows)
    await flush()
    exportToJson(rows)
    await flush()
    exportToMarkdown(rows)
    await flush()
    expect(downloads).toHaveLength(3)
    expect(downloads[0].filename).toMatch(/\.csv$/)
    expect(downloads[1].filename).toMatch(/\.json$/)
    expect(downloads[2].filename).toMatch(/\.md$/)
  })
})
