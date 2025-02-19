const API_KEY = "2383baf758f2bb5776fee29fa80a940e766c96296d701cd1c1f3d664fb275819"; // Replace with your actual VirusTotal API key
const BLOCK_DURATION = 1 * 60 * 1000; // 1 minute (change as needed)
const navigationStates = {};

// ✅ Set an alarm that runs every minute to check for expired blocked sites
chrome.alarms.create("clearExpiredBlocks", { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "clearExpiredBlocks") {
        console.log("⏳ Checking for expired blocked sites...");
        clearExpiredBlockedSites();
    }
});

// ✅ Function to clear expired blocked sites
function clearExpiredBlockedSites() {
    chrome.storage.local.get(["blockedSites"], (data) => {
        let blockedSites = data.blockedSites || {};
        const now = Date.now();
        let updatedSites = {};

        Object.keys(blockedSites).forEach((site) => {
            const blockTime = blockedSites[site];
            if (now - blockTime < BLOCK_DURATION) {
                updatedSites[site] = blockTime; // Keep unexpired blocks
            } else {
                console.log(`🟢 Unblocking site: ${site} (Blocked for ${((now - blockTime) / 1000).toFixed(1)} sec)`);
            }
        });

        chrome.storage.local.set({ blockedSites: updatedSites }, () => {
            console.log("✅ Expired blocked sites removed.");
            updateBlockRules();
        });
    });
}

// ✅ Function to block a site
async function blockSite(url, tabId) {
    let mainDomain = extractMainDomain(url);

    chrome.storage.local.get(["blockedSites"], (data) => {
        let blockedSites = data.blockedSites || {};
        blockedSites[mainDomain] = Date.now();

        chrome.storage.local.set({ blockedSites }, () => {
            console.log(`🚫 Blocked ${mainDomain} for ${BLOCK_DURATION / 60000} minutes.`);
            updateBlockRules();
            if (tabId) {
                chrome.tabs.remove(tabId); // Close the tab instead of redirecting
            }
        });
    });
}

// ✅ Function to check if a site is already blocked
async function isBlocked(url) {
    let mainDomain = extractMainDomain(url);

    return new Promise((resolve) => {
        chrome.storage.local.get(["blockedSites"], (data) => {
            const blockedSites = data.blockedSites || {};
            resolve(blockedSites[mainDomain] && Date.now() - blockedSites[mainDomain] < BLOCK_DURATION);
        });
    });
}

// ✅ Function to update Chrome's block rules
async function updateBlockRules() {
    chrome.declarativeNetRequest.getDynamicRules((rules) => {
        const existingRuleIds = rules.map(rule => rule.id);

        // First, remove all existing rules
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingRuleIds,
            addRules: []
        }, () => {
            console.log(`🟢 Cleared all previous blocking rules.`);

            chrome.storage.local.get(["blockedSites"], (data) => {
                let blockedSites = data.blockedSites || {};
                let newRules = Object.keys(blockedSites).map((site, index) => ({
                    "id": index + 1,
                    "priority": 1,
                    "action": { "type": "block" },
                    "condition": { "urlFilter": site, "resourceTypes": ["main_frame"] }
                }));

                chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: [],
                    addRules: newRules
                }, () => {
                    console.log(`✅ Updated blocking rules. Active blocked sites: ${Object.keys(blockedSites).length}`);
                });
            });
        });
    });
}

// ✅ Function to extract the main domain from a URL
function extractMainDomain(url) {
    try {
        return new URL(url).hostname;
    } catch (err) {
        console.error("Error parsing URL:", err);
        return null;
    }
}

// ✅ Function to check URL with VirusTotal
async function checkUrlWithVirusTotal(url) {
    console.log("🔍 Checking URL with VirusTotal:", url);

    try {
        const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: "POST",
            headers: {
                accept: 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'x-apikey': API_KEY
            },
            body: new URLSearchParams({ url: url })
        });

        if (!submitResponse.ok) {
            console.error(`❌ Failed to submit URL: ${submitResponse.statusText}`);
            return { isMalicious: false, stats: null };
        }

        const submitData = await submitResponse.json();
        const reportId = submitData.data.id;

        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait for processing

        const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${reportId}`, {
            method: 'GET',
            headers: {
                accept: 'application/json',
                'x-apikey': API_KEY
            }
        });

        if (!reportResponse.ok) {
            console.error(`❌ Failed to fetch VirusTotal report: ${reportResponse.statusText}`);
            return { isMalicious: false, stats: null };
        }

        const reportData = await reportResponse.json();
        const stats = reportData.data.attributes.stats;
        const isMalicious = stats.malicious > 0;

        if (isMalicious) {
            return true;
        }
        else {
            return false;
        }

    } catch (err) {
        return { isMalicious: false, stats: null };
    }
}

// ✅ Intercept navigation and enforce blocking
chrome.webNavigation.onCommitted.addListener(async (details) => {
    const { tabId, url, frameId } = details;
    if (frameId !== 0 || tabId === -1) return;

    if (await isBlocked(url)) {
        console.warn(`🚫 Blocking access to ${url}`);
        chrome.tabs.remove(tabId);
        return;
    }

    if (navigationStates[tabId] === url) return;
    navigationStates[tabId] = url;

    const isMalicious = await processURL(url, tabId);
    

    chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ["content.js"]
    }, () => {
        chrome.tabs.sendMessage(tabId, {
            url,
            isMalicious,
        });
    });

    delete navigationStates[tabId];
},
{ urls: ["<all_urls>"], types: ["main_frame"] } // Monitor all URLs
);

// ✅ Handle messages from content.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "block") {
        blockSite(message.url, sender.tab.id);
    } else if (message.action === "closeTab") {
        if (sender.tab && sender.tab.id) {
            chrome.tabs.remove(sender.tab.id);
        }
    }
});

async function processURL(url, tabId) {

    const mainDomain = extractMainDomain(url);
    if (!mainDomain || mainDomain == "newtab" || mainDomain == "devtools" || mainDomain == "new-tab-page") return;

    console.log("Domain detected:", mainDomain);

    let result = await checkSiteStatus(mainDomain);
    if (result) {
        console.log('Site is malicious (Finally)');
        return true;
    }
    else {
        console.log('Site is safe (Finally)');
        return false;
    }
}

async function checkURLWithDB(url) {
    console.log(`Checking ${url} with DB`);
    
    try {
        const response = await fetch(`http://20.2.161.111:4000/check?url=${url}`);
        const data = await response.json();
        
        if (!data.stored) {
            console.log('Site cannot be found in DB');
            return false;  // Returning true if malicious
        }
        else {
            console.log('Site is whitelisted');
            return true;  // Returning false if safe
        }
    }
    catch (err) {
        console.error('Error checking domain: ', err);
        return null;  // Returning null in case of error (so it can fallback to VirusTotal)
    }
}

async function checkSiteStatus(mainDomain) {
    try {
        // First, check if the URL is in the database
        const stored = await checkURLWithDB(mainDomain);

        // If the domain is found in the database
        if (stored) {
            console.log('Site is whitelisted');
            return false;
        }
        else {
            // If domain was not found in the DB, check with VirusTotal
            console.log('Site not found in DB, checking with VirusTotal');
            const virusTotalResult = await checkUrlWithVirusTotal(mainDomain);
            
            // Return the result from VirusTotal
            if (virusTotalResult) {
                console.log('Site is Malicious (From VirusTotal)');
                return true;
            }
            else {
                console.log('Site is Safe (From VirusTotal)');
                addURLToDB(mainDomain);
                return false;
            }
        }
    }
    catch (error) {
        console.error('Error checking URL:', error);
        return false;
    }
}

async function addURLToDB(url) {
    console.log(`Adding ${url} to DB`);

    try {
        // If the domain is not found in DB, insert it
        const insertResponse = await fetch('http://20.2.161.111:4000/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url
            })
        });

        const insertData = await insertResponse.json();
        if (insertData.success) {
            console.log(`Domain ${url} added to DB`);
        } else {
            console.log('Failed to add domain to DB');
        }
    } catch (err) {
        console.error('Error adding domain to DB: ', err);
    }
}


  chrome.webRequest.onBeforeSendHeaders.addListener(
    async function (details) {
      const excludedDomain = "virustotal.com";
      const isExcludedDomain = details.url.includes(excludedDomain);
      if (!isExcludedDomain){
      const hasCSRF = details.requestHeaders.some(header =>
        header.name.toLowerCase() === "x-csrf-token"
      );
  
      if (!hasCSRF) {
        const message = `🚨 Possible CSRF vulnerability detected on:\n${details.url}\n\nDo you want to proceed?`;
  
        // Query the active tab
        let tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs.length === 0) return;
  
        // Send message to content.js and wait for a response
        let response = await new Promise((resolve) => {
            chrome.tabs.sendMessage(tabs[0].id, { 
                action: "showSecurityPopup", 
                message: message, 
                url: details.url 
            }, resolve);
        });
  
        // If user denies, block the request
        if (response && response.userAllowed === false) {
            let mainDomain = extractMainDomain(details.url); // Extract main domain like VirusTotal does
            if (mainDomain) {
                await blockSite(mainDomain, tabs[0].id); // Ensure it's added to blockedSites
            }

            return { cancel: true }; // 🚫 Block request
        }
      }
    }
else{
    console.log("Skipping CSRF check for domain:", excludedDomain);
}
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders"]
  );


  chrome.cookies.onChanged.addListener(function (changeInfo) {
    if (!changeInfo.removed) {
      const cookie = changeInfo.cookie;
  
      // Check if it's a session cookie (no expiration date)
      const isSessionCookie = !cookie.expirationDate;
  
      // Check security flags
      const isSecure = cookie.secure;
      const isHttpOnly = cookie.httpOnly;
  
      // Warn if session cookie is insecure
      if (isSessionCookie && (!isSecure || !isHttpOnly)) {
        //console.warn("[SESSION ALERT] Insecure session cookie detected:", cookie);
        const message = `[SESSION ALERT] Insecure session cookie detected: ${cookie}`;
        
        // Send a message to content.js to show the popup
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
          if (tabs.length === 0) return; // No active tabs found             
          const tabUrl = tabs[0].url;  
          chrome.tabs.sendMessage(tabs[0].id, { action: "showSecurityPopup", message: message, url: tabUrl }, function (response) {
            // Wait for the user response before proceeding with blocking the request
            if (response && !response.userAllowed) {
                let mainDomain = extractMainDomain(tabUrl); // Extract main domain like VirusTotal does
                if (mainDomain) {
                  blockSite(mainDomain, tabs[0].id); // Ensure it's added to blockedSites
                }
              // Block the request if user denied
              return { cancel: true };
            }
          });
        });
      }
  
    
  
      console.log("Cookie set:", cookie);
    }
  });



// ✅ Function to check SQL Injection

const sqlPayloadList = [
    `' OR '1'='1`,
    `" OR "1"="1`,
    `' OR '1'='1' --`,
    `" OR "1"="1" --`,
    `admin' --`,
    `' OR 1=1 --`,
    `1' or '1' = '1`,
    `') OR ('1'='1`,
    `1; DROP TABLE users --`,
    `1; SELECT * FROM information_schema.tables --`,
    `' OR 'x'='x`,
    `") OR ("x"="x`,
    `' UNION SELECT NULL, NULL, NULL --`,
    `' AND 1=CONVERT(int, (SELECT @@version)) --`,
    `' AND (SELECT COUNT(*) FROM users) > 0 --`,
    `' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --`
];

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
          if (
                    responsetext.includes("SQL syntax") ||
                    responsetext.includes("Unclosed quotation mark") ||
                    responsetext.includes("Unknown column") ||
                    responsetext.includes("mysql_fetch") ||
                    responsetext.includes("You have an error in your SQL syntax") ||
                    responsetext.includes("Warning: mysql") ||
                    responsetext.includes("ODBC SQL Server Driver") ||
                    responsetext.match(/column .* does not exist/i)
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

// ✅ Handle messages from popup.js
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === "checkSQL") {
        const result = await checkSQLInjection(message.url);
        sendResponse(result);
    }
});
  
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === "checkXSS") {
        const url = message.url;

        if (!url.includes("?")) {
            sendResponse({ isVulnerable: false, report: [] });
            return;
        }

        console.log(`Checking XSS for URL: ${url}`);

        const xssPayloadList = [
            `<script>alert('XSS')</script>`,
            `"><script>alert('XSS')</script>`,
            `' onmouseover='alert("XSS")'`,
            `javascript:alert('XSS')`,
            `<img src="x" onerror="alert('XSS')">`
        ];

        const parsedUrl = new URL(url);
        const params = parsedUrl.searchParams;
        let vuln = false;
        let detailedReport = [];

        for (const [key, value] of params) {
            for (const payload of xssPayloadList) {
                const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
                console.log(`Testing: ${testUrl}`);
                
                try {
                    const response = await fetch(testUrl);
                    const responseText = await response.text();

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
                            response: "Possible XSS vulnerability"
                        });
                        break;
                    }
                } catch (err) {
                    console.error(`Error testing ${testUrl}:`, err);
                }
            }
        }

        sendResponse({ isVulnerable: vuln, report: detailedReport });
    }
    return true; // Required for async response
});
