chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (!message || !message.url) return;

  let warnings = [];

  // If VirusTotal marked the site as malicious, add warning
  if (message.isMalicious) {
      warnings.push(`🚨 WARNING: The site "${message.url}" is flagged as malicious by VirusTotal.`);
  }

  // Run CSRF and XSS checks
  if (message.checkCSRF || message.checkXSS) {
      let csrfDetected = checkCSRF();
      let xssDetected = checkXSS();

      if (csrfDetected) warnings.push(`⚠️ Possible CSRF vulnerability detected on ${message.url}`);
      if (xssDetected) warnings.push(`⚠️ Possible XSS vulnerability detected on ${message.url}`);
  }

  // If no warnings, return early
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

  return true;
});

// CSRF Detection Logic
function checkCSRF() {
  let forms = document.querySelectorAll("form");
  for (let form of forms) {
      if (!form.querySelector("[name='csrf_token']")) {
          return true; // CSRF vulnerability detected
      }
  }
  return false;
}

// XSS Detection Logic
function checkXSS() {
  let scripts = document.querySelectorAll("script");
  for (let script of scripts) {
      if (script.innerHTML.includes("<script>") || script.innerHTML.includes("onerror") || script.innerHTML.includes("alert(")) {
          return true; // XSS vulnerability detected
      }
  }
  return false;
}
