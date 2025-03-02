import { extractMainDomain } from './extraMainURL.js';
import { checkUrlWithVirusTotal } from './virusTotalCheck.js';

export const pendingCsrfWarnings = {};
const pendingSessionCookieWarnings = {};

export async function checkMalicious(url) {
  const mainDomain = extractMainDomain(url);
  if (!mainDomain) return "";
  
  console.log(`Running VirusTotal check for: ${mainDomain}`);
  const virusTotalResult = await checkUrlWithVirusTotal(mainDomain);

  return virusTotalResult ? `WARNING: The site "${url}" is flagged as malicious.` : "";
}


// CSRF check that uses the warning stored from onBeforeSendHeaders
// export async function checkCsrf(url, tabId) {
//   if (pendingCsrfWarnings[tabId]) {
//     const warning = pendingCsrfWarnings[tabId];
//     delete pendingCsrfWarnings[tabId];
//     return warning;
//   }
//   return "";
// }

// Session cookie check that uses the warning stored from chrome.cookies.onChanged
export async function checkSessionCookie(url, tabId) {
  if (pendingSessionCookieWarnings[tabId]) {
    const warning = pendingSessionCookieWarnings[tabId];
    delete pendingSessionCookieWarnings[tabId];
    return warning;
  }
  return "";
}

// Aggregator: run all security checks concurrently and collect warnings
export async function runAllSecurityChecks(url, tabId) {
  // If not whitelisted (or an error occurred), run the additional security checks concurrently.
  const results = await Promise.all([
    checkMalicious(url),
    //checkCsrf(url, tabId),
    //checkSessionCookie(url, tabId)
    // Add additional checks here as needed.
  ]);
  return results.filter(msg => msg !== "");
}