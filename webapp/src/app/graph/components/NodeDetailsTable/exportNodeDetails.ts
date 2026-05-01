import type { TableRow } from '../../hooks/useTableData'
import {
  timestampSlug,
  downloadBlob,
  flattenCellValue,
  escapeMarkdownCell,
  toCsv,
  CSV_MIME,
} from '../../utils/exportHelpers'

export interface NodeDetailsExportInput {
  nodeType: string
  rows: TableRow[]
  /** Sorted list of visible dynamic property keys (after applying user hide prefs). */
  visibleDynamicKeys: string[]
  /** Whether the In count column is currently visible. */
  showIn: boolean
  /** Whether the Out count column is currently visible. */
  showOut: boolean
}

interface BuiltExport {
  headers: string[]
  rows: Record<string, unknown>[]
}

function slugForType(nodeType: string): string {
  return nodeType.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'nodes'
}

function buildExportData(input: NodeDetailsExportInput): BuiltExport {
  const headers: string[] = ['Name', ...input.visibleDynamicKeys]
  if (input.showIn) headers.push('In')
  if (input.showOut) headers.push('Out')

  const rows = input.rows.map(row => {
    const out: Record<string, unknown> = { Name: row.node.name }
    for (const key of input.visibleDynamicKeys) {
      out[key] = row.node.properties[key]
    }
    if (input.showIn) out.In = row.connectionsIn.length
    if (input.showOut) out.Out = row.connectionsOut.length
    return out
  })

  return { headers, rows }
}

export function exportNodeDetailsCsv(input: NodeDetailsExportInput): void {
  const { headers, rows } = buildExportData(input)
  const csv = toCsv(headers, rows)
  downloadBlob(
    csv,
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.csv`,
    CSV_MIME,
  )
}

export function exportNodeDetailsJson(input: NodeDetailsExportInput): void {
  const { headers, rows } = buildExportData(input)
  // Preserve column order in the JSON object by re-projecting through `headers`.
  const ordered = rows.map(row => {
    const o: Record<string, unknown> = {}
    for (const h of headers) o[h] = row[h] ?? null
    return o
  })
  const payload = {
    nodeType: input.nodeType,
    generatedAt: new Date().toISOString(),
    columns: headers,
    rows: ordered,
  }
  downloadBlob(
    JSON.stringify(payload, null, 2),
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
  )
}

export function exportNodeDetailsMarkdown(input: NodeDetailsExportInput): void {
  const { headers, rows } = buildExportData(input)
  const headerLine = `| ${headers.join(' | ')} |`
  const sepLine = `| ${headers.map(() => '---').join(' | ')} |`
  const dataLines = rows.map(row =>
    `| ${headers.map(h => escapeMarkdownCell(flattenCellValue(row[h]))).join(' | ')} |`,
  )

  const md =
    `# ${input.nodeType} — Node Inspector Export\n\n` +
    `Generated: ${new Date().toISOString()}\n` +
    `Rows: ${rows.length}\n\n` +
    `${headerLine}\n${sepLine}\n${dataLines.join('\n')}\n`

  downloadBlob(
    md,
    `redamon-${slugForType(input.nodeType)}-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
  )
}

// Exposed for unit tests (no DOM I/O).
export const __testing = { buildExportData, slugForType }
