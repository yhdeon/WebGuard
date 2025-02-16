// content.js
console.log("Content script loaded!");

// chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
//   if (message && message.url) {
//       if (message.isMalicious) {
//           let userConfirmed = window.confirm(
//               `🚨 WARNING: The site "${message.url}" is flagged as malicious! 🚨\nDo you want to proceed?`
//           );

//           if (!userConfirmed) {
//               chrome.runtime.sendMessage({ action: "block", url: message.url });

//               // Log block action instead of modifying the page
//               console.log(`🚫 User refused to proceed. Blocking: ${message.url}`);

//               sendResponse({ proceed: false });
//           } else {
//               console.log(`✅ User chose to continue: ${message.url}`);
//               sendResponse({ proceed: true });
//           }
//       } else {
//           sendResponse({ proceed: true });
//       }
//   } else {
//       sendResponse({ proceed: true });
//   }

//   return true;
// });


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
            showSecurityPopup(message).then((userAllowed) => {
                if (!userAllowed) {
                    node.remove();  // 🚨 Block execution
                } else {
                    console.log("User allowed the script.");
                }
            });
        }
  
            //  Detect inline event handlers (XSS)
            if (node.outerHTML.includes("onerror") || node.outerHTML.includes("onload")) {
              showSecurityPopup(`[XSS Alert] Suspicious event-based script detected: ${node.outerHTML}`).then((userAllowed) => {
                if (!userAllowed) {
                    node.remove();
                }
            });
        }
  
            // 🔍 Detect auto-submitting forms (CSRF)
            if (node.tagName === "FORM" && node.hasAttribute("action")) {
              if (node.hasAttribute("autofill") || node.outerHTML.includes("onsubmit")) {
                showSecurityPopup(`[CSRF Alert] Suspicious form submission detected: ${node.outerHTML}`).then((userAllowed) => {
                  if (!userAllowed) {
                      console.log("User blocked the CSRF form submission.");
                  }
              });
          }
      }
  
            // 🔍 Detect suspicious hidden iframe/image requests (CSRF)
            if (node.tagName === "IFRAME" || node.tagName === "IMG") {
              if (node.src && !node.src.startsWith(window.location.origin)) {
                showSecurityPopup(`[CSRF Alert] Suspicious external request via iframe/img: ${node.src}`).then((userAllowed) => {
                  if (!userAllowed) {
                      console.log("User blocked the suspicious external request.");
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



  function showSecurityPopup(message, callback) {
    // Create overlay
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(0,0,0,0.7)";
    overlay.style.zIndex = "9999";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";

    // Create modal
    const modal = document.createElement("div");
    modal.style.backgroundColor = "white";
    modal.style.padding = "20px";
    modal.style.borderRadius = "8px";
    modal.style.textAlign = "center";
    modal.style.boxShadow = "0px 0px 10px rgba(0,0,0,0.3)";
    modal.innerHTML = `
        <h2>⚠️ Security Warning</h2>
        <p>${message}</p>
        <button id="allowButton" style="padding: 10px 20px; margin: 10px; background-color: green; color: white; border: none; cursor: pointer;">Allow</button>
        <button id="blockButton" style="padding: 10px 20px; margin: 10px; background-color: red; color: white; border: none; cursor: pointer;">Block</button>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Handle button clicks
    document.getElementById("allowButton").addEventListener("click", function () {
        document.body.removeChild(overlay);
        resolve(true);
    });

    document.getElementById("blockButton").addEventListener("click", function () {
        alert("Access blocked due to security concerns.");
        document.body.removeChild(overlay);
        resolve(false);
    });
}

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.action === "showSecurityPopup") {
    const message = request.message;
    // Show the security popup and wait for the response
    showSecurityPopup(message).then(userAllowed => {
      sendResponse({ userAllowed: userAllowed });
    });
    return true; // Keep the message channel open for asynchronous response
  } 

  else if (request.url && request.isMalicious) {
    let userConfirmed = window.confirm(
      `🚨 WARNING: The site "${request.url}" is flagged as malicious! 🚨\nDo you want to proceed?`
    );

    if (!userConfirmed) {
      chrome.runtime.sendMessage({ action: "block", url: request.url });
      console.log(`🚫 User refused to proceed. Blocking: ${request.url}`);
      sendResponse({ proceed: false });
    } else {
      console.log(`✅ User chose to continue: ${request.url}`);
      sendResponse({ proceed: true });
    }
  } else {
    sendResponse({ proceed: true });
  }

  return true; // Keep the message channel open for both handlers
});

  