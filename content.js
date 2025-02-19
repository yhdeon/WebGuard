chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message) return;

    let warnings = [];

    // 🚨 If VirusTotal marked the site as malicious, add a warning
    if (message.isMalicious) {
        warnings.push(`🚨 WARNING: The site "${message.url}" is flagged as malicious by VirusTotal.`);
    }

    // 🚨 If the background script detects a CSRF issue
    if (message.action === "showSecurityPopup") {
        let userConfirmed = window.confirm(message.message);
        sendResponse({ userAllowed: userConfirmed });

        if (!userConfirmed) {
            // 🚫 If the user cancels, block the site
            chrome.runtime.sendMessage({ action: "block", url: message.url });
            console.log(`🚫 User refused CSRF warning. Blocking: ${message.url}`);
            chrome.runtime.sendMessage({ action: "closeTab" });
        }

        return true; // Keep the message channel open
    }

    // If no warnings, proceed normally
    if (warnings.length === 0) {
        sendResponse({ proceed: true });
        return;
    }

    // Show a single popup with all warnings
    let warningMessage = warnings.join("\n\n") + "\n\nDo you want to proceed?";
    let userConfirmed = window.confirm(warningMessage);

    if (!userConfirmed) {
        chrome.runtime.sendMessage({ action: "block", url: message.url });
        console.log(`🚫 User refused to proceed. Blocking: ${message.url}`);
        sendResponse({ proceed: false });

        // Close the tab instead of redirecting
        chrome.runtime.sendMessage({ action: "closeTab" });
    } else {
        console.log(`✅ User chose to continue: ${message.url}`);
        sendResponse({ proceed: true });
    }

    return true; // Keep the message channel open
});





function monitorDOMForSecurity() {
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    // Detect injected scripts (XSS)
                    if (node.tagName === "SCRIPT") {
                        const message = `[XSS Alert] Suspicious script added: ${node}`;
                        showSecurityPopup(message).then((userAllowed) => {
                            if (!userAllowed) {
                                // If user cancels, block the webpage
                                chrome.runtime.sendMessage({ action: "block" });
                            }
                        });
                    }

                    // Detect inline event handlers (XSS)
                    if (node.outerHTML.includes("onerror") || node.outerHTML.includes("onload")) {
                        const message = `[XSS Alert] Suspicious event-based script detected: ${node.outerHTML}`;
                        showSecurityPopup(message).then((userAllowed) => {
                            if (!userAllowed) {
                                // If user cancels, block the webpage
                                chrome.runtime.sendMessage({ action: "block" });
                            }
                        });
                    }

                    // Detect auto-submitting forms (CSRF)
                    if (node.tagName === "FORM" && node.hasAttribute("action")) {
                        if (node.hasAttribute("autofill") || node.outerHTML.includes("onsubmit")) {
                            const message = `[CSRF Alert] Suspicious form submission detected: ${node.outerHTML}`;
                            showSecurityPopup(message).then((userAllowed) => {
                                if (!userAllowed) {
                                    console.log("User blocked the CSRF form submission.");
                                    chrome.runtime.sendMessage({ action: "block" });
                                }
                            });
                        }
                    }

                    // Detect suspicious hidden iframe/image requests (CSRF)
                    if (node.tagName === "IFRAME" || node.tagName === "IMG") {
                        if (node.src && !node.src.startsWith(window.location.origin)) {
                            const message = `[CSRF Alert] Suspicious external request via iframe/img: ${node.src}`;
                            showSecurityPopup(message).then((userAllowed) => {
                                if (!userAllowed) {
                                    console.log("User blocked the suspicious external request.");
                                    chrome.runtime.sendMessage({ action: "block" });
                                }
                            });
                        }
                    }
                }
            });
        });
    });

    observer.observe(document, { childList: true, subtree: true });
}


  function showSecurityPopup(message) {
    return new Promise((resolve) => {
        // Display a confirmation dialog
        const userConfirmed = window.confirm(message);
        resolve(userConfirmed); // Resolve the promise based on user input
    });
}

// Start monitoring when the page loads
    window.addEventListener("load", () => {
        monitorDOMForSecurity();
      });

function detectInput() {
        const emailFields = document.querySelectorAll('input[type="email"], input[name="email"]');
        if (emailFields.length > 0) {
            console.log("Email input field detected.");
            console.log("No. of email fields: " + emailFields.length);
            let payload = "' OR '1'='1'; -- ";  // SQL Injection payload for testing
    
            emailFields.forEach(input => {
                input.value = payload;  // Inject payload
                input.dispatchEvent(new Event('input', { bubbles: true }));  // Simulate user typing
            });
    
            // Using fetch to test SQL injection without submitting the form
            var forms = document.querySelectorAll('form');
            forms.forEach(form => {
                let actionURL = form.action;
                let formData = new FormData(form);
    
                fetch(actionURL, {
                    method: form.method || 'POST',
                    body: formData,
                    credentials: "include"
                })
                .then(response => response.text())
                .then(text => {
                    console.log("SQL Injection Test Response:", text);
                    if (
                        text.includes("SQL syntax error") || 
                        text.includes("unclosed quotation mark") || 
                        text.includes("database error") ||
                        text.match(/column .* does not exist/i)
                    ) {
                        
                        const message = `High confidence website is vulnerable to SQL Injection! ${node.src}`;
                        showSecurityPopup(message).then((userAllowed) => {
                            if (!userAllowed) {
                                console.log("User blocked the suspicious external request.");
                                chrome.runtime.sendMessage({ action: "block" });
                                chrome.runtime.sendMessage({ action: "closeTab" });
                            }
                        });

                    }
                })
                .catch(err => console.error("Error testing SQL injection:", err));
            });
        } else {
            console.log("No email input fields detected.");
        }
    }
    
    function detectPwdInput() {
        const passwordFields = document.querySelectorAll('input[type="password"], input[name="password"]');
        if (passwordFields.length > 0) {
            console.log("Password input field detected.");
            console.log("No. of password fields: " + passwordFields.length);
        } else {
            console.log("No password input fields detected.");
        }
    }
    
    // Run the detection functions
    detectInput();
    detectPwdInput();
    // run the xss and sql injection detection functions (URL MODE)
    chrome.runtime.sendMessage({ action: "checkSQL", url: url }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Error sending message:", chrome.runtime.lastError.message);
        } else if (response) {
            if (response.vulnerable) {
               
                htmlOutput.textContent = `⚠️ WARNING: This site might be vulnerable to SQL Injection!\n\n${JSON.stringify(stats, null, 2)}`;
            } else {
                
                htmlOutput.textContent = `✅ No SQL Injection Vulnerabilities detected.\n\n${JSON.stringify(stats, null, 2)}`;
            }
        }
    });

    // Send message to check for XSS vulnerabilities
    chrome.runtime.sendMessage({ action: "checkXSS", url: url }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Error sending XSS request:", chrome.runtime.lastError.message);
        } else if (response) {
            if (response.isVulnerable) {
                
                htmlOutput.textContent = `⚠️ WARNING: This site might be vulnerable to XSS!\n\n${JSON.stringify(stats, null, 2)}`;
            } else {
                
                htmlOutput.textContent = `✅ No XSS Vulnerabilities detected.\n\n${JSON.stringify(stats, null, 2)}`;
            }
        }
    });
    

