import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Mask a secret string to show only the last 4 characters. */
function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

const TUNNEL_FIELDS = ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

// GET /api/users/[id]/settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    let settings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    if (!settings) {
      // Return empty defaults (don't create yet)
      return NextResponse.json({
        tavilyApiKey: '',
        shodanApiKey: '',
        serpApiKey: '',
        nvdApiKey: '',
        vulnersApiKey: '',
        urlscanApiKey: '',
        ngrokAuthtoken: '',
        chiselServerUrl: '',
        chiselAuth: '',
      })
    }

    if (!internal) {
      // Mask secrets for frontend (chiselServerUrl is not a secret)
      settings = {
        ...settings,
        tavilyApiKey: maskSecret(settings.tavilyApiKey),
        shodanApiKey: maskSecret(settings.shodanApiKey),
        serpApiKey: maskSecret(settings.serpApiKey),
        nvdApiKey: maskSecret(settings.nvdApiKey),
        vulnersApiKey: maskSecret(settings.vulnersApiKey),
        urlscanApiKey: maskSecret(settings.urlscanApiKey),
        ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
        chiselAuth: maskSecret(settings.chiselAuth),
      }
    }

    return NextResponse.json(settings)
  } catch (error) {
    console.error('Failed to fetch user settings:', error)
    return NextResponse.json(
      { error: 'Failed to fetch user settings' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/settings - Upsert user settings
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    // If a masked value is sent back, preserve the existing value
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    const data: Record<string, string> = {}
    const fields = ['tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey', 'vulnersApiKey', 'urlscanApiKey', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

    for (const field of fields) {
      if (field in body) {
        const val = body[field] as string
        // If the value starts with '••••', keep existing
        if (val.startsWith('••••') && existing) {
          data[field] = existing[field]
        } else {
          data[field] = val
        }
      }
    }

    const settings = await prisma.userSettings.upsert({
      where: { userId: id },
      update: data,
      create: { userId: id, ...data },
    })

    // Push tunnel config to kali-sandbox if any tunnel field actually changed.
    // A field "changed" if: (a) it's in the request body, AND (b) the new value
    // written to `data[f]` differs from the previous DB value in `existing[f]`.
    // Note: masked values (••••) are resolved to existing values above, so
    // unchanged masked fields correctly compare as equal here.
    const tunnelChanged = TUNNEL_FIELDS.some(f => f in body && data[f] !== (existing?.[f] ?? ''))
    if (tunnelChanged) {
      try {
        await fetch('http://kali-sandbox:8015/tunnel/configure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ngrokAuthtoken: settings.ngrokAuthtoken,
            chiselServerUrl: settings.chiselServerUrl,
            chiselAuth: settings.chiselAuth,
          }),
        })
      } catch (e) {
        console.warn('Failed to push tunnel config to kali-sandbox:', e)
      }
    }

    // Return masked (chiselServerUrl is not a secret)
    return NextResponse.json({
      ...settings,
      tavilyApiKey: maskSecret(settings.tavilyApiKey),
      shodanApiKey: maskSecret(settings.shodanApiKey),
      serpApiKey: maskSecret(settings.serpApiKey),
      nvdApiKey: maskSecret(settings.nvdApiKey),
      vulnersApiKey: maskSecret(settings.vulnersApiKey),
      urlscanApiKey: maskSecret(settings.urlscanApiKey),
      ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
      chiselAuth: maskSecret(settings.chiselAuth),
    })
  } catch (error) {
    console.error('Failed to update user settings:', error)
    return NextResponse.json(
      { error: 'Failed to update user settings' },
      { status: 500 }
    )
  }
}
