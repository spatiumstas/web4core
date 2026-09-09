function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".local")) return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = ipv4.slice(1).map(Number);
    if (a === 127 || a === 10 || a === 0 || a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  return false;
}

export default {
    async fetch(request) {
      const url = new URL(request.url);
      const target = url.searchParams.get("url") || url.searchParams.get("url");
      
      if (!target) return new Response("Add ?url=URL", { status: 400 });

      let targetUrl;
      try {
        targetUrl = new URL(target);
      } catch {
        return new Response("Invalid url", { status: 400 });
      }
      if (!["http:", "https:"].includes(targetUrl.protocol) || isBlockedHost(targetUrl.hostname)) {
        return new Response("URL not allowed", { status: 400 });
      }
  
      const response = await fetch(targetUrl.toString(), {
        headers: {
          "User-Agent": "curl/8.7.1",
          "Accept": "*/*",
          "Accept-Encoding": "identity",
          "Connection": "close"
        }
      });
  
      return new Response(response.body, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store"
        }
      });
    }
  };