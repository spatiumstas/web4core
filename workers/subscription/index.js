export default {
    async fetch(request) {
      const url = new URL(request.url);
      const target = url.searchParams.get("url") || url.searchParams.get("url");
      
      if (!target) return new Response("Add ?url=URL", { status: 400 });
  
      const response = await fetch(target, {
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