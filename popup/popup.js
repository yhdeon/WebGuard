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

  // Scan for input fields (email/password detection)
  scanButton.addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs.length > 0) {
              const tab = tabs[0];

              chrome.scripting.executeScript({
                  target: { tabId: tab.id },
                  func: () => {
                      function detectInput() {
                          const emailFields = document.querySelectorAll('input[type="email"], input[name="email"]');
                          if (emailFields.length > 0) {
                              console.log("Email input field detected.");
                              console.log("No. of email fields: " + emailFields.length);
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

                      detectInput();
                      detectPwdInput();
                  },
              }, (results) => {
                  if (chrome.runtime.lastError) {
                      console.error("Error executing script:", chrome.runtime.lastError.message);
                  } else {
                      console.log("Script executed successfully:", results);
                  }
              });
          } else {
              console.error("No active tab found.");
          }
      });
  });
});
