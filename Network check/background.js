// Check HTTPS enforcement
chrome.webRequest.onBeforeRequest.addListener(
    function (details) {
      if (details.url.startsWith("http://")) {
        console.warn("Insecure connection detected:", details.url);
      }
    },
    { urls: ["<all_urls>"] }
  );
  
  // Monitor cookies sent to unknown domains
  chrome.cookies.onChanged.addListener(function (changeInfo) {
    if (changeInfo.removed === false) {
      console.log("Cookie set:", changeInfo.cookie);
    }
  });
  
  // Check for missing CSRF tokens
  chrome.webRequest.onBeforeSendHeaders.addListener(
    function (details) {
      const hasCSRF = details.requestHeaders.some(header => 
        header.name.toLowerCase() === "x-csrf-token"
      );
  
      if (!hasCSRF) {
        console.warn("Possible CSRF vulnerability detected:", details.url);
      }
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders"]
  );
  