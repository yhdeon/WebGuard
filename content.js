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


// content.js

// Function to monitor DOM for security risks (XSS, CSRF)
function monitorDOMForSecurity() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Detect injected scripts (XSS)
            if (node.tagName === "SCRIPT") {
              const message = `[XSS Alert] Suspicious script added: ${node}`;
              const userResponse = confirm(message);
              if (userResponse) {
                console.log("User acknowledged the script issue.");
              }
              node.remove();  // 🚨 Block execution
            }
  
            //  Detect inline event handlers (XSS)
            if (node.outerHTML.includes("onerror") || node.outerHTML.includes("onload")) {
              const message = `[XSS Alert] Suspicious event-based script detected: ${node.outerHTML}`;
              const userResponse = confirm(message);
              if (userResponse) {
                console.log("User acknowledged the inline event handler issue.");
              }
              node.remove();
            }
  
            // 🔍 Detect auto-submitting forms (CSRF)
            if (node.tagName === "FORM" && node.hasAttribute("action")) {
              if (node.hasAttribute("autofill") || node.outerHTML.includes("onsubmit")) {
                const message = `[CSRF Alert] Suspicious form submission detected: ${node}`;
                const userResponse = confirm(message);
                if (userResponse) {
                  console.log("User acknowledged the CSRF form issue.");
                }
              }
            }
  
            // 🔍 Detect suspicious hidden iframe/image requests (CSRF)
            if (node.tagName === "IFRAME" || node.tagName === "IMG") {
              if (node.src && !node.src.startsWith(window.location.origin)) {
                const message = `[CSRF Alert] Suspicious external request via iframe/img: ${node.src}`;
                const userResponse = confirm(message);
                if (userResponse) {
                  console.log("User acknowledged the CSRF iframe/img issue.");
                }
              }
            }
          }
        });
      });
    });
  
    observer.observe(document, { childList: true, subtree: true });
  }
  

  
  // Check for CSRF vulnerabilities (detect auto-submit forms and external requests)
  function checkCSRF(document) {
    // Check for suspicious forms (auto-submitting, with suspicious attributes)
    const forms = document.querySelectorAll("form[action]");
    forms.forEach((form) => {
      if (form.hasAttribute("autofill") || form.outerHTML.includes("onsubmit")) {
        const message = `[CSRF Alert] Suspicious form submission detected: ${form}`;
        const userResponse = confirm(message);
        if (userResponse) {
          console.log("User acknowledged the CSRF form submission issue.");
        }
      }
    });
  
    // Check for suspicious external requests via iframes or images
    const iframes = document.querySelectorAll("iframe, img");
    iframes.forEach((node) => {
      if (node.src && !node.src.startsWith(window.location.origin)) {
        const message = `[CSRF Alert] Suspicious external request via iframe/img: ${node.src}`;
        const userResponse = confirm(message);
        if (userResponse) {
          console.log("User acknowledged the CSRF iframe/img issue.");
        }
      }
    });
  }
  
  // Start monitoring when the page loads
  window.addEventListener("load", () => {
    monitorDOMForSecurity();
  });
  