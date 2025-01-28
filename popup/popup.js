// test - detecting <input> fields for email and password
document.getElementById("Scan").addEventListener("click", () => {
    // Query the active tab in the current window
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
          // get the current tab url
          
            const [tab] = /*await*/ chrome.tabs.query({ active: true, currentWindow: true });
            const url = tab.url;
            // Execute a script in the context of the current tab
            chrome.scripting.executeScript({
                target: { tabId: tabs[0].id },
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
                }
            });

            // output the result in a div 
            chrome.runtime.sendMessage({ action: "scan", url }, (response) => {
                const resultDiv = document.getElementById("result");
                resultDiv.innerHTML = `
                    
                    <p><strong>Heuristic Check:</strong> ${response.heuristicCheck}</p>
                `;
            });
        } else {
            console.error("No active tab found.");
        }
    });
});