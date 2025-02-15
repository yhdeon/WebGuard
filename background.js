const API_KEY = "YOUR-API-KEY"; // Replace with your actual VirusTotal API key
const BLOCK_DURATION = 1 * 60 * 1000; // 15 minutes
const navigationStates = {};

// Extract main domain from a URL
function extractMainDomain(url) {
    try {
        return new URL(url).hostname;
    } catch (err) {
        console.error("Error parsing URL:", err);
        return null;
    }
}

// Check if a site is already blocked
async function isBlocked(url) {
    return new Promise((resolve) => {
        chrome.storage.local.get(["blockedSites"], (data) => {
            const blockedSites = data.blockedSites || {};
            resolve(blockedSites[url] && Date.now() - blockedSites[url] < BLOCK_DURATION);
        });
    });
}

// Block a site for 15 minutes
async function blockSite(url) {
    chrome.storage.local.get(["blockedSites"], (data) => {
        let blockedSites = data.blockedSites || {};
        blockedSites[url] = Date.now();
        chrome.storage.local.set({ blockedSites }, () => {
            console.log(`🚫 Blocked ${url} for ${BLOCK_DURATION / 60000} minutes.`);
        });
    });
}

// Clear expired blocked sites
chrome.alarms.create("clearBlockedSites", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(() => {
    chrome.storage.local.get(["blockedSites"], (data) => {
        let blockedSites = data.blockedSites || {};
        const now = Date.now();
        Object.keys(blockedSites).forEach((url) => {
            if (now - blockedSites[url] >= BLOCK_DURATION) {
                delete blockedSites[url];
            }
        });
        chrome.storage.local.set({ blockedSites });
    });
});

// Check URL with VirusTotal
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
            console.error(`Failed to submit URL: ${submitResponse.statusText}`);
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
            console.error(`Failed to fetch VirusTotal report: ${reportResponse.statusText}`);
            return { isMalicious: false, stats: null };
        }

        const reportData = await reportResponse.json();
        const stats = reportData.data.attributes.stats;
        const isMalicious = stats.malicious > 0;

        return { isMalicious, stats };
    } catch (err) {
        console.error("Error checking URL with VirusTotal:", err);
        return { isMalicious: false, stats: null };
    }
}

// Intercept navigation and scan before allowing access
chrome.webNavigation.onCommitted.addListener(async (details) => {
    const { tabId, url, frameId } = details;
    if (frameId !== 0) return;

    if (await isBlocked(url)) {
        console.warn(`User is trying to access a blocked site: ${url}`);
        chrome.tabs.update(tabId, { url: "about:blank" });
        return;
    }

    if (navigationStates[tabId] === url) {
        console.log(`Already scanning: ${url}`);
        return;
    }
    navigationStates[tabId] = url;

    const result = await checkUrlWithVirusTotal(url);

    if (result.isMalicious) {
        console.log(`Malicious site detected: ${url}`);

        // Inject content script and prompt the user
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ["content.js"]
        }, () => {
            chrome.tabs.sendMessage(tabId, { url, isMalicious: true }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error(`Error sending message: ${chrome.runtime.lastError.message}`);
                    return;
                }

                if (response && response.proceed === false) {
                    blockSite(url);
                    chrome.tabs.update(tabId, { url: "about:blank" });
                    console.log("Site blocked and user redirected.");
                } else {
                    console.log(`User chose to continue: ${url}`);
                }
            });
        });
    } else {
        console.log(`✅ Safe site: ${url}`);
    }

    delete navigationStates[tabId];
});
