chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.url) {
        // Show the confirmation dialog
        const userConfirmed = confirm(`Do you want to proceed to: ${message.url}?`);

        // Respond to the background script with the user's choice
        sendResponse({ proceed: userConfirmed });
    }
});
