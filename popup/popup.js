document.addEventListener('DOMContentLoaded', function () {
  const htmlOutput = document.getElementById('htmlOutput');

  document.getElementById("status").innerText = "Monitoring Network Security...";

  // Retrieve the VirusTotal result from storage
  chrome.storage.local.get('virusTotalResult', (data) => {
    if (data.virusTotalResult) {
      const { url, isMalicious, stats } = data.virusTotalResult;
      console.log(url);

      if (isMalicious) {
        htmlOutput.textContent = `Warning: The URL "${url}" is malicious!\n\n${JSON.stringify(stats, null, 2)}`;
      } else {
        htmlOutput.textContent = `The URL "${url}" is safe.\n\n${JSON.stringify(stats, null, 2)}`;
      }
    } else {
      htmlOutput.textContent = "No URL has been checked yet.";
    }
  });
});

// test - detecting <input> fields for email and password
document.getElementById("Scan").addEventListener("click", () => {
  // Query the active tab in the current window
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      // const [tab] = /*await*/ chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0]; //using the first active tab
      const url = tab.url;

      // Execute a script in the context of the current tab
      chrome.scripting.executeScript({
        // target: { tabId: tabs[0].id },
        target:{tabId: tab.id},
        func: () => {
          function detectInput() {
            var input_emailfield = document.querySelectorAll('input[name="email"]');
            if (input_emailfield.length > 0) {
              console.log("Input field detected");
              console.log("No. of input fields: " + input_emailfield.length);
            } else {
              console.log("No input field detected");
            }
          };

          function detectPwdInput() {
            var input_pwdfield = document.querySelectorAll('input[name="password"]');
            if (input_pwdfield.length > 0) {
              console.log("Password field detected");
              console.log("No. of password fields: " + input_pwdfield.length);
            } else {
              console.log("No password field detected");
            }
          };

          detectInput();
          detectPwdInput();
        },
      });
      //output result of url check - chris
      // chrome.runtime.sendMessage({ action: "scan", url }, (response) => {
      //   const resultDiv = document.getElementById("result");
      //   resultDiv.innerHTML = `
      //             <p><strong>Heuristic Check:</strong> ${response.heuristicCheck}</p>
      //         `;
      // });
      (results) => {
        if (chrome.runtime.lastError) {
          console.error("Error executing script:", chrome.runtime.lastError.message);
        } else {
          console.log("Script executed successfully:", results);
        }
      }
    } else {
      console.error("No active tab found.");
    }
  });
});