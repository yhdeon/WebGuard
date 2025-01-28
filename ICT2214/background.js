// Track navigation states to avoid duplicate prompts
const navigationStates = {};

chrome.webNavigation.onCommitted.addListener((details) => {
    const { tabId, url, frameId } = details;

    // Only handle top-level navigations (frameId === 0 ensures it's the main frame)
    if (frameId !== 0) return;

    // Check if the navigation has already been handled
    if (navigationStates[tabId] === url) {
        console.log(`Navigation already handled for: ${url}`);
        return;
    }

    // Mark this navigation as handled
    navigationStates[tabId] = url;

    // Dynamically inject content.js before sending a message
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

                // Remove the navigation state after handling
                delete navigationStates[tabId];
            });
        }
    );
});

// Clear navigation states when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
    delete navigationStates[tabId];
});
