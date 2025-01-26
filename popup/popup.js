// test - detecting <input> fields for email and password
document.getElementById("Scan").addEventListener("click", () => {
    // Query the active tab in the current window
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
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
                },
            });
        } else {
            console.error("No active tab found.");
        }
    });
});