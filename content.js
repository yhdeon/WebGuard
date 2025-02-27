// content.js

// Combine all the warning together
function displayWarningPopup(warnings, url) {
  const message = warnings.join("\n\n") + "\n\nDo you want to proceed?";
  const userConfirmed = window.confirm(message);
  if (!userConfirmed) {
    chrome.runtime.sendMessage({ action: "block", url });
    chrome.runtime.sendMessage({ action: "closeTab" });
  } else {
    console.log(`✅ User chose to proceed with ${url}`);
  }
}

let aggregatedWarnings = [];
let warningPopupTimeout;

function addAggregatedWarning(warning) {
  aggregatedWarnings.push(warning);
  // Clear any previously scheduled popup
  if (warningPopupTimeout) {
    clearTimeout(warningPopupTimeout);
  }
  // Schedule a consolidated popup after a short delay (e.g., 1 second)
  warningPopupTimeout = setTimeout(() => {
    if (aggregatedWarnings.length > 0) {
      displayWarningPopup(aggregatedWarnings, window.location.href);
      aggregatedWarnings = [];
    }
  }, 1000);
}

// ---------------------- DOM Check ----------------------

function monitorDOMForSecurity() {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Detect injected scripts (XSS)
          if (node.tagName === "SCRIPT") {
            const message = `[XSS Alert] Suspicious script added: ${node.src || node.outerHTML}`;
            addAggregatedWarning(message);
          }

          // Detect inline event handlers (XSS)
          if (node.outerHTML.includes("onerror") || node.outerHTML.includes("onload")) {
            const message = `[XSS Alert] Suspicious event-based script detected: ${node.outerHTML}`;
            addAggregatedWarning(message);
          }

          // Detect auto-submitting forms (CSRF)
          if (node.tagName === "FORM" && node.hasAttribute("action")) {
            if (node.hasAttribute("autofill") || node.outerHTML.includes("onsubmit")) {
              const message = `[CSRF Alert] Suspicious form submission detected: ${node.outerHTML}`;
              addAggregatedWarning(message);
            }
            const formAction = node.action;
            if (!formAction.startsWith(window.location.origin)){
              const message = `[CSRF Alert] Suspicious form submission detected: ${node.outerHTML}`;
              addAggregatedWarning(message);
            }
          }

          // Detect suspicious hidden iframe/image requests (CSRF)
          if (node.tagName === "IFRAME" || node.tagName === "IMG") {
            if (node.src && !node.src.startsWith(window.location.origin)) {
              const message = `[CSRF Alert] Suspicious external request via iframe/img: ${node.src}`;
              addAggregatedWarning(message);
            }
          }
        }
      });
    });
  });

  observer.observe(document, { childList: true, subtree: true });
}



window.addEventListener("load", () => {
  monitorDOMForSecurity();
  // add the trigger here
  detectInput();
  detectPwdInput();
});

// ---------------------- SQL XSS Check ----------------------

const url = window.location.href;
let SQLWarning = [];

function detectInput() {
  const sqlPayloadList = [
    // `' OR '1'='1`,
    // `" OR "1"="1`,
    // `' OR '1'='1' --`,
    // `" OR "1"="1" --`,
     `admin' --`
    // `' OR 1=1 --`,
    // `1' or '1' = '1`,
    // `') OR ('1'='1`,
    // `1; DROP TABLE users --`,
    // `1; SELECT * FROM information_schema.tables --`,
    // `' OR 'x'='x`,
    // `") OR ("x"="x`,
    // `' UNION SELECT NULL, NULL, NULL --`,
    // `' AND 1=CONVERT(int, (SELECT @@version)) --`,
    // `' AND (SELECT COUNT(*) FROM users) > 0 --`,
    // `' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --`
  ];
  
  
  
  const usernameFields = document.querySelectorAll('input[name="id"]');
  // const usernameFields = document.querySelectorAll('input[type="text"]');
  if (usernameFields.length > 0) {
      console.log("Username input field detected.");
      console.log("No. of username fields: " + usernameFields.length);
      let tocontinue = true;
      

      // Iterate over each payload in sqlPayloadList
      for (let i = 0; i < sqlPayloadList.length && tocontinue == true; i++) {
          const payload = sqlPayloadList[i];
          
          console.log(`Testing payload: ${payload}`);
   
          
          if (tocontinue){
            
          

          usernameFields.forEach(input => {
              input.value = payload;  // Inject payload into input field
              input.dispatchEvent(new Event('input', { bubbles: true }));  // Simulate user typing
          });

          // Test SQL Injection for each form
          document.querySelectorAll('form').forEach(form => {
            
              let actionURL = form.action || window.location.href;
              let fetchOptions = {
                  method: form.method.toUpperCase() || 'POST',
                  credentials: "include"
              };

              if (fetchOptions.method === "GET") {
                  // Convert form data to URL parameters and inject payload
                  let url = new URL(actionURL);
                  url.searchParams.set("id", payload);  // Inject payload into username param
                  url.searchParams.set("Submit", "Submit");  
                  actionURL = url.toString();
              } else {
                  // Prepare FormData and inject payload
                  let formData = new FormData(form);
                  formData.set("id", payload);
                  
                  fetchOptions.body = formData;
              }
              console.log(actionURL);
              fetch(actionURL, fetchOptions)
                  .then(response => response.text())
                  .then(text => {
                      //console.log("SQL Injection Test Response:", text);
                     //console.log("Am here");
                      if (
                        text.includes("SQL syntax error") || 
                        text.includes("unclosed quotation mark") || 
                        text.includes("database error") ||
                        text.match(/column .* does not exist/i) ||
                        text.includes("unexpected end of SQL command") ||
                        text.includes("unterminated quoted string") ||
                        text.includes("error in your SQL syntax") ||
                        text.includes("Warning: mysql_") ||
                        text.includes("You have an error in your SQL syntax") ||
                        text.includes("PG::SyntaxError") || 
                        text.includes("ERROR: syntax error") || 
                        text.includes("ERROR: unterminated quoted string") ||
                        text.includes("PostgreSQL query failed") ||
                        text.includes("Microsoft SQL Native Client error") ||
                        text.includes("ODBC SQL Server Driver") ||
                        text.includes("Incorrect syntax near") ||
                        text.includes("Unclosed quotation mark after the character string") ||
                        text.includes("ORA-00933: SQL command not properly ended") ||
                        text.includes("ORA-00904: invalid identifier") ||
                        text.includes("SQLite3::SQLException") ||
                        text.includes("no such column") ||
                        text.includes("syntax error near") ||
                        text.includes("MariaDB server version for the right syntax to use") ||
                        text.includes("View '...' references invalid table(s) or column(s)") ||
                        text.includes("Fatal error: Uncaught exception") || 
                        text.includes("Warning: pg_query()") || 
                        text.includes("Invalid SQL statement")
                      ) {
                        
                          message = ` High confidence: Website is vulnerable to SQL Injection! Payload: ${payload}`;
                          //addAggregatedWarning(message);
                          //SQLWarning.push(message);
                          //addAggregatedWarning(message);
                          
                          //stop the loop
                          tocontinue = false;
                          console.log(tocontinue);
                          console.log(SQLWarning);
                         displayWarningPopup([message], window.location.href);
                         //displayWarningPopup([message], window.location.href);
                        
                      }
                      else{
                        //console.log("Am here now test.");
                      }
                      
                      
                  }) 
                  .catch(err => console.error("Error testing SQL injection:", err));
          });

        } else {
          console.log("SQL Injection Test stopped.");
        }




      }; 
      
     
    

  } else {
      console.log("No username input fields detected.");
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

// run the xss and sql injection detection functions (URL MODE)
chrome.runtime.sendMessage({ action: "checkSQL", url: url }, (response) => {
  if (chrome.runtime.lastError) {
      console.error("Error sending message:", chrome.runtime.lastError.message);
  } else if (response) {
      if (response.vulnerable) {
         
          //htmlOutput.textContent = ` WARNING: This site might be vulnerable to SQL Injection!\n\n${JSON.stringify(response.report, null, 2)}`;
          const message = ` WARNING: This site might be vulnerable to SQL Injection! ${node.outerHTML}`;
          addAggregatedWarning(message);
      } else {
          console.log("No SQL Injection Vulnerabilities detected.");
         
          
          //htmlOutput.textContent = ` No SQL Injection Vulnerabilities detected.\n\n${JSON.stringify(stats, null, 2)}`;
      }
  }
});

// Send message to check for XSS vulnerabilities
chrome.runtime.sendMessage({ action: "checkXSS", url: url }, (response) => {
  if (chrome.runtime.lastError) {
      console.error("Error sending XSS request:", chrome.runtime.lastError.message);
  } else if (response) {
      if (response.isVulnerable) {
          
          //htmlOutput.textContent = ` WARNING: This site might be vulnerable to XSS!\n\n${JSON.stringify(stats, null, 2)}`;
          const message = `  WARNING: This site might be vulnerable to XSS! ${node.outerHTML}`;
          addAggregatedWarning(message);
      } else {
          console.log("No XSS Vulnerabilities detected.");
          //htmlOutput.textContent = ` No XSS Vulnerabilities detected.\n\n${JSON.stringify(stats, null, 2)}`;
      }
  }
});

