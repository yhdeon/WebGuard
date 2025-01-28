// background.js
chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension installed successfully!");
  });

 //added by chris 28/1/25 1630H
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