// content.js
console.log("Content script loaded!");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.url) {
        // Show the confirmation dialog
        const userConfirmed = confirm(`SITE IS MALICIOUS!!! Do you want to continue to: ${message.url}?`);

        // Respond to the background script with the user's choice
        sendResponse({ proceed: userConfirmed });
    }
});