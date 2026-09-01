import { sha256 } from './js/sha256.js';

// EdgeOne Makers Middleware to inject environment variables
export async function middleware(context) {
  const { request, env, next } = context;

  // Get the URL from the request
  const url = new URL(request.url);

  // Only process HTML pages
  const isHtmlPage = url.pathname.endsWith('.html') || url.pathname.endsWith('/');
  if (!isHtmlPage) {
    return next(); // Let the request pass through unchanged
  }

  // Get the original response
  const response = await next();

  // Check if it's an HTML response
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) {
    return response; // Return the original response if not HTML
  }

  // Get the HTML content
  const originalHtml = await response.text();

  // Replace the placeholder with actual environment variable
  // If PASSWORD is not set, replace with empty string
  const password = env.PASSWORD || '';
  let passwordHash = '';
  if (password) {
    passwordHash = await sha256(password);
  }

  const adminpassword = env.ADMINPASSWORD || '';
  let adminpasswordHash = '';
  if (adminpassword) {
    adminpasswordHash = await sha256(adminpassword);
  }

  // Merge the two replacements into one operation
  let modifiedHtml = originalHtml
    .replace(
      'window.__ENV__.PASSWORD = "{{PASSWORD}}";',
      `window.__ENV__.PASSWORD = "${passwordHash}"; // SHA-256 hash`
    )
    .replace(
      'window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";',
      `window.__ENV__.ADMINPASSWORD = "${adminpasswordHash}"; // SHA-256 hash`
    );

  // Return the modified response
  return new Response(modifiedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });
}

export const config = {
  matcher: ['/', '/((?!api|_next/static|_vercel|favicon.ico).*)'],
};
