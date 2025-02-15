chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed successfully!");
});

// Add your VirusTotal API key here
const API_KEY = "ADD-API-KEY-HERE";

const urlVisited = [];

const firstUrlPerTab = new Map();

// List of possible payloads for SQL injection (can add more if can think of any)
const sqlpayloadlist = [
  "' OR 1=1--",
  "' UNION SELECT NULL, NULL--",
  "' AND 1=1--",
  "' OR 'a'='a",
  "' AND '1'='2"
];

// List of possible payloads for XSS (can add more if can think of any) (THIS PART I HAVENT TEST YET)
const xsspayloadlist = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>"
];

//added by chris 28/1/25
// Detect suspicious heuristics in the URL
// function detectSuspiciousHeuristics(url) {
//   const domain = new URL(url).hostname;
//   const flags = [];
//   if (domain.includes("--") || domain.split("-").length > 3) {
//     flags.push("Too many hyphens in domain");
//   }
//   if (/0|1|!|@/.test(domain)) {
//     flags.push("Suspicious characters (e.g., 0, 1, @)");
//   }
//   if (domain.length > 50) {
//     flags.push("Domain too long");
//   }
//   return flags.length > 0 ? `Suspicious: ${flags.join(", ")}` : "No suspicious heuristics detected";
// };

// // window.location.href returns the href (URL) of the current page
// detectSuspiciousHeuristics(window.location.href);

// // Main scan function (combines checks)
// function scanURL(url) {
//   const domainCheck = checkDomain(url);
//   const heuristicCheck = detectSuspiciousHeuristics(url);
//   return {
//     domainCheck,
//     heuristicCheck
//   };
// }

// Function to extract the main domain from a URL
function extractMainDomain(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname; // e.g., "www.youtube.com"
    return hostname;
  } catch (err) {
    console.error("Error parsing URL: ", err);
    return null;
  }
}

// Function to check URL with VirusTotal
async function checkUrlWithVirusTotal(url, tabId) {
  console.log("Checking the following URL with VirusTotal: ", url);
  const submitOption = {
    method: "POST",
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
      'x-apikey': API_KEY
    },
    body: new URLSearchParams({ url: url }) // Include the URL in the request body
  };

  try {
    // Step 1: Submit the URL for analysis
    console.log("Entering Step 1");
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', submitOption);
    if (!submitResponse.ok) {
      throw new Error(`Failed to submit URL: ${submitResponse.statusText}`);
    }

    const submitData = await submitResponse.json();
    const reportId = submitData.data.id; // Extract the report ID for analysis

    // Step 2: Fetch the analysis report using report ID
    console.log("Entering Step 2");
    const reportOptions = {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'x-apikey': API_KEY
      }
    };

    const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${reportId}`, reportOptions);
    if (!reportResponse.ok) {
      throw new Error(`Failed to fetch report: ${reportResponse.statusText}`);
    }

    const reportData = await reportResponse.json();

    // Step 3: Check if the URL is malicious
    console.log("Entering Step 3");
    const stats = reportData.data.attributes.stats;
    const isMalicious = stats.malicious > 0;

    // Save the result to Chrome storage
    chrome.storage.local.set({ virusTotalResult: { url, isMalicious, stats } }, () => {
      console.log("VirusTotal result saved: ", { url, isMalicious, stats });

      // If the URL is malicious, inject the content script and show a confirmation dialog
      if (isMalicious) {
        chrome.scripting.executeScript(
          {
            target: { tabId: tabId },
            files: ["content.js"],
          },
          () => {
            if (chrome.runtime.lastError) {
              console.error(`Failed to inject content script: ${chrome.runtime.lastError.message}`);
              return;
            }

            // Send a message to the content script to show the confirmation dialog
            chrome.tabs.sendMessage(tabId, { url }, (response) => {
              if (response && response.proceed === false) {
                // Cancel navigation by closing the tab
                chrome.tabs.remove(tabId, () => {
                  console.log("Navigation canceled by the user.");
                });
              } else {
                console.log(`User confirmed navigation to: ${url}`);
              }
            });
          }
        );
      }
    });
  } catch (err) {
    console.error("Error checking URL with VirusTotal: ", err);
  }
}

// Listen for web requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
      const { tabId, url, frameId } = details;

      // Only handle top-level navigations (frameId === 0 ensures it's the main frame)
      if (frameId !== 0) return;

      if (tabId != -1) {
          processURL(details.url, tabId);
      }
  },
  { urls: ["<all_urls>"], types: ["main_frame"]} // Monitor all URLs
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
      processURL(changeInfo.url);
  }
});

// Clean up when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  firstUrlPerTab.delete(tabId); // Remove the tab's entry from the map
  console.log("Tab closed, removed from tracking:", tabId);
});

// Used to process the URLs entered before sending it to VirusTotal for checking.
function processURL(url, tabId) {

  const mainDomain = extractMainDomain(url);
  if (!mainDomain || mainDomain == "newtab") return;

  console.log("Domain detected:", mainDomain);

  if (urlVisited.includes(mainDomain)) {
      console.log(`${mainDomain} was already visited.`);
  }
  else {
      urlVisited.push(mainDomain);
      console.log("Added to list:", mainDomain);
      checkUrlWithVirusTotal(mainDomain, tabId);
  }
}

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


// chris
// chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
//   if (message.action === "scan") {
//     const result = scanURL(message.url);
//     sendResponse(result);
//   }
// });


// Analyze a URL for vulnerable query parameters (meant for URL specifically)
async function checkSQLInjection(url) {
  const parsedUrl = new URL(url);
  const params = parsedUrl.searchParams;
  let vuln = false;
  let theresult = [];
  for (const [key, value] of params) {
    for (const payload of sqlpayloadlist) {
      const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
      console.log(`Testing: ${testUrl}`);
      try {
        const response = await fetch(testUrl);
        const responsetext = await response.text();
        // some heuristic checker thing
        if (
          responsetext.includes("SQL syntax") ||
          responsetext.includes("Unclosed quotation mark") ||
          responsetext.includes("Unknown column")
        ) {
          vuln = true;
          theresult.push({
            parameter: key,
            payload,
            response: "SQL error detected"
          });
          break;
        }
      } catch (err) {
        console.error(`Error testing ${testUrl}:`, err);
      }
    }
  }
  return {
    isVulnerable: vuln,
    report: theresult
  };
}
// Sql Injection scan tester for textboxes in the web form

// Listen for scan requests
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.action === "checkSQL") {
    const result = await checkSQLInjection(message.url);
    sendResponse(result);
  }
});

// Analyze a URL for vulnerable query parameters
async function checkXSS(url) {
  const parsedUrl = new URL(url);
  const params = parsedUrl.searchParams;
  let vuln = false;
  let detailedReport = [];
  for (const [key, value] of params) {
    for (const payload of xsspayloadlist) {
      const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
      console.log(`Testing: ${testUrl}`);
      try {
        const response = await fetch(testUrl);
        const responseText = await response.text();
        // Heuristic: Look for XSS-related error messages
        if (
          responseText.includes("script") ||
          responseText.includes("alert") ||
          responseText.includes("onerror") ||
          responseText.includes("onload")
        ) {
          vuln = true;
          detailedReport.push({
            parameter: key,
            payload,
            response: "XSS payload"
          });
          break;
        }
      } catch (err) {
        console.error(`Error testing ${testUrl}:`, err);
      }
    }
  }
  return {
    isVulnerable: vuln,
    report: detailedReport
  };
}