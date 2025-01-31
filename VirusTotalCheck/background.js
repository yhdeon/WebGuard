const API_KEY = "2383baf758f2bb5776fee29fa80a940e766c96296d701cd1c1f3d664fb275819"; // Add your VirusTotal API key here

let firstUrl = null;

const firstUrlPerTab = new Map();

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
    console.log("Checking the following URL: ", url);
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

        // Check if this is the first request for this tab
        if (!firstUrlPerTab.has(tabId)) {
            firstUrlPerTab.set(tabId, url); // Mark this tab's first URL
            console.log("First URL for tab", tabId, ":", url);

            // Extract the main domain
            const mainDomain = extractMainDomain(url);
            if (mainDomain) {
                console.log("Main domain extracted: ", mainDomain);

                // Check the URL with VirusTotal
                checkUrlWithVirusTotal(mainDomain, tabId);
            }
        }
    },
    { urls: ["<all_urls>"] } // Monitor all URLs
);

// Clean up when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    firstUrlPerTab.delete(tabId); // Remove the tab's entry from the map
    console.log("Tab closed, removed from tracking:", tabId);
});

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        console.log("Getting first url");
        // Capture the first URL
        if (!firstUrl) {
            firstUrl = details.url;
            console.log("Intercepted URL: ", firstUrl);

            // Extract the main domain
            const mainDomain = extractMainDomain(firstUrl);
            if (mainDomain) {
                console.log("Main domain extracted: ", mainDomain);

                // Check the URL with VirusTotal
                checkUrlWithVirusTotal(mainDomain);
            }
        }
    },
    { urls: ["<all_urls>"]} // Monitor all URLs
);