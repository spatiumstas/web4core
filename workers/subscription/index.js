export default {
    async fetch(request) {
      const corsHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "x-hwid, x-device-model"
      };
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

      const url = new URL(request.url);
      const target = url.searchParams.get("url") || url.searchParams.get("url");
      
      if (!target) return new Response("Add ?url=URL", { status: 400 });
  
      const headers = {
        "User-Agent": "curl/8.7.1",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close"
      };
      for (const name of ["x-hwid", "x-device-model"]) {
        const value = request.headers.get(name);
        if (value) headers[name] = value;
      }
      const response = await fetch(target, { headers });
  
      return new Response(response.body, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          ...corsHeaders,
          "Cache-Control": "no-store"
        }
      });
    }
  };
