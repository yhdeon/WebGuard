document.addEventListener('DOMContentLoaded', function () {
    const htmlOutput = document.getElementById('htmlOutput');
    const statusDiv = document.getElementById("status");
    const scanButton = document.getElementById("Scan");
  
    statusDiv.innerText = "Checking site security...";
  
    // Query the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            const tab = tabs[0];
            const url = tab.url;
  
            // Retrieve stored VirusTotal results
            chrome.storage.local.get('virusTotalResult', (data) => {
                if (data.virusTotalResult && data.virusTotalResult.url === url) {
                    const { isMalicious, stats } = data.virusTotalResult;
                    if (isMalicious) {
                        htmlOutput.textContent = `⚠️ WARNING: This site is malicious!\n\n${JSON.stringify(stats, null, 2)}`;
                    } else {
                        htmlOutput.textContent = `✅ This site is safe.\n\n${JSON.stringify(stats, null, 2)}`;
                    }
                } else {
                    htmlOutput.textContent = "🔍 No scan results available.";
                }
            });
        } else {
            htmlOutput.textContent = "❌ No active tab detected.";
        }
    });
  });
  