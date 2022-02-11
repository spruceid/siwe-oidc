import { getAssetFromKV, mapRequestToAsset } from '@cloudflare/kv-asset-handler'

const DEBUG = false

addEventListener('fetch', event => {
  event.respondWith(handleEvent(event))
})

async function handleEvent(event) {
  let options = {}
  options.mapRequestToAsset = spaRouting()
  options.cacheControl = {
    bypassCache: DEBUG,
  }

  try {
    const page = await getAssetFromKV(event, options)
    const response = new Response(page.body, page)
    response.headers.set('X-XSS-Protection', '1; mode=block')
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('Referrer-Policy', 'unsafe-url')
    response.headers.set('Feature-Policy', 'none')
    return response
  } catch (e) {
    return new Response(e.message || e.toString(), { status: 500 })
  }
}

function spaRouting() {
  return request => {
    let defaultAssetKey = mapRequestToAsset(request)
    let url = new URL(defaultAssetKey.url)
    if (url.pathname.includes(".html")) {
      url.pathname = "/index.html"
    }
    return new Request(url.toString(), defaultAssetKey)
  }
}
