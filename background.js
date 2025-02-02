// background.js
chrome.runtime.onInstalled.addListener(() => {
  console.log("Extension installed successfully!");
});

//added by chris 28/1/25
// Detect suspicious heuristics in the URL
function detectSuspiciousHeuristics(url) {
  const domain = new URL(url).hostname;
  const flags = [];
  if (domain.includes("--") || domain.split("-").length > 3) {
    flags.push("Too many hyphens in domain");
  }
  if (/0|1|!|@/.test(domain)) {
    flags.push("Suspicious characters (e.g., 0, 1, @)");
  }
  if (domain.length > 50) {
    flags.push("Domain too long");
  }
  return flags.length > 0 ? `Suspicious: ${flags.join(", ")}` : "No suspicious heuristics detected";
};

detectSuspiciousHeuristics(window.location.href);

// Main scan function (combines checks)
function scanURL(url) {
  const domainCheck = checkDomain(url);
  const heuristicCheck = detectSuspiciousHeuristics(url);
  return {
    domainCheck,
    heuristicCheck
  };
}

// Listen for button click
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scan") {
    const result = scanURL(message.url);
    sendResponse(result);
  }
});

// List of possible payloads for SQL injection (can add more if can think of any)
const sqlpayloadlist = [
  "' OR 1=1--",
  "' UNION SELECT NULL, NULL--",
  "' AND 1=1--",
  "' OR 'a'='a",
  "' AND '1'='2"
];

// Analyze a URL for vulnerable query parameters (meant for URL specifically)
async function checkSQLInjection(url) {
  const parsedUrl = new URL(url);
  const params = parsedUrl.searchParams;

  let vuln = false;
  let theresult = [];

  for (const [key, value] of params) {
      for (const payload of sqlpayloadlist) {
          const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
          console.log(`Testing: ${testUrl}`);

          try {
              const response = await fetch(testUrl);
              const responsetext = await response.text();

              // some heuristic checker thing
              if (
                  responsetext.includes("SQL syntax") ||
                  responsetext.includes("Unclosed quotation mark") ||
                  responsetext.includes("Unknown column")
              ) {
                  vuln = true;
                  theresult.push({
                      parameter: key,
                      payload,
                      response: "SQL error detected"
                  });
                  break;
              }
          } catch (err) {
              console.error(`Error testing ${testUrl}:`, err);
          }
      }
  }

  return {
      isVulnerable: vuln,
      report: theresult
  };
}
// Maybe a function to scan for forms to check?

// Sql Injection scan tester for textboxes in the web form

async function checkFormSQLInjection(formSelector) {
  const form = document.querySelector(formSelector);
  // check if a form exist 
  if (!form) {
    console.error('Form not found');
    return;
  }
  // the type of inputs that i want to check (text, password and text area, can put more if need)
  const inputs = form.querySelectorAll('input[type="text"], input[type="password"], textarea');
  let vuln = false;
  let theresult = [];

  for (const input of inputs) {
    for (const payload of sqlpayloadlist) {
      const originalValue = input.value;
      input.value = payload;

      try {
        const response = await fetch(form.action, {
          method: form.method,
          body: new FormData(form),
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });

        const responsetext = await response.text();

        // Heuristic checker
        if (
          responsetext.includes("SQL syntax") ||
          responsetext.includes("Unclosed quotation mark") ||
          responsetext.includes("Unknown column")
        ) {
          vuln = true;
          theresult.push({
            input: input.name,
            payload,
            response: "SQL error detected"
          });
          break;
        }
      } catch (err) {
        console.error(`Error testing input ${input.name}:`, err);
      } finally {
        input.value = originalValue; // Restore original value
      }
    }
  }

  return {
    isVulnerable: vuln,
    report: theresult
  };
}

// Listen for scan requests
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.action === "checkSQL") {
      const result = await checkSQLInjection(message.url);
      sendResponse(result);
  }
});

// List of possible payloads for XSS (can add more if can think of any) (THIS PART I HAVENT TEST YET)
const xsspayloadlist = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>"
];

// Analyze a URL for vulnerable query parameters
async function checkXSS(url) {
  const parsedUrl = new URL(url);
  const params = parsedUrl.searchParams;

  let vuln = false;
  let detailedReport = [];

  for (const [key, value] of params) {
      for (const payload of xsspayloadlist) {
          const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
          console.log(`Testing: ${testUrl}`);

          try {
              const response = await fetch(testUrl);
              const responseText = await response.text();

              // Heuristic: Look for XSS-related error messages
              if (
                  responseText.includes("script") ||
                  responseText.includes("alert") ||
                  responseText.includes("onerror") ||
                  responseText.includes("onload")
              ) {
                  vuln = true;
                  detailedReport.push({
                      parameter: key,
                      payload,
                      response: "XSS payload"
                  });
                  break;
              }
          } catch (err) {
              console.error(`Error testing ${testUrl}:`, err);
          }
      }
  }

  return {
      isVulnerable: vuln,
      report: detailedReport
  };
}
