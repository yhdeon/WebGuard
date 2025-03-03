const navigationStates = {};



import { clearExpiredBlockedSites, blockSite, isBlocked } from './background_script/temporaryBlock.js';
import { clearExpiredWhitelistedSites, addTemporaryWhitelist, isTemporarilyWhitelisted} from './background_script/temporaryWhitelist.js';
import { checkMalicious,  checkSessionCookie, runAllSecurityChecks, pendingCsrfWarnings} from './background_script/initialSecurityCheck.js';
import { checkURLWithDB, addURLToDB} from './background_script/whitelistDatabase.js';
import { fetchFile, checkFileHashWithVirusTotal, analyzeZipFile, saveFile} from './background_script/downloadCheck.js';

import * as JSZip from './libs/jszip.min.js';
// import {checkSQLInjection} from './background_script/SQLICheck.js'
// import { extractMainDomain } from './extraMainURL.js';
// import { checkUrlWithVirusTotal } from './virusTotalCheck.js';

let globalFlag = true;

// -------------------- set "alarm" to run those 2 function which clear expired block site and expire whitelist site-------------------------------------
chrome.alarms.create("clearExpiredSutes", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "clearExpiredSutes") {
    console.log("Checking for expired blocked sites...");
    clearExpiredBlockedSites();
    clearExpiredWhitelistedSites();
  }
});



// ---------------------- check current tab is it whitelisted or block ----------------------
// if whitelisted, skip pass all the initial security check
// blacklisted, disallow entry to the site
chrome.webNavigation.onCommitted.addListener(async (details) => {
  const { tabId, url, frameId } = details;
  if (frameId !== 0 || tabId === -1) return;

  const permanentlyWhitelisted = await checkURLWithDB(url);
  const temporarilyWhitelisted = await isTemporarilyWhitelisted(url);

  if (permanentlyWhitelisted || temporarilyWhitelisted) {
    console.log(`Site ${url} is whitelisted. Skipping security checks.`);
    return;
  }

  if (await isBlocked(url)) {
    console.warn(`Block access to ${url}`);
    chrome.tabs.remove(tabId);
    return;
  }

  if (navigationStates[tabId] === url) return;
  navigationStates[tabId] = url;

  const warnings = await runAllSecurityChecks(url, tabId);

  if (warnings.length > 0) {
    // consolidate all the initial security check's message then generate to 1 popup
    chrome.scripting.executeScript({
      target: { tabId },
      func: (warnings, url) => {
        const message = warnings.join("\n\n") + "\n\nDo you want to proceed?";
        const userConfirmed = window.confirm(message);
        if (!userConfirmed) {
          chrome.runtime.sendMessage({ action: "block", url }); // disallow to enter the site. however for the amount of time we set
          chrome.runtime.sendMessage({ action: "closeTab" }); // will straight close the tab
        } else {
          console.log(`User chose to proceed with ${url}`);
          chrome.runtime.sendMessage({ action: "whitelist", url }); //temporary whitelist the site
        }
      },
      args: [warnings, url]
    });
  } else {
    // 
    console.log(`Site ${url} passed all security checks. Adding to whitelist.`); // 
    addURLToDB(url);
  }

  delete navigationStates[tabId];
}, { urls: ["<all_urls>"], types: ["main_frame"] });


// ---------------------- CSRF Check via onBeforeSendHeaders ----------------------
chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    const excludedDomain = "virustotal.com";
    console.log("in csrf func")
    if (details.url.includes(excludedDomain)) return;
    if (globalFlag === false) return;
    if (["POST", "PUT", "DELETE"].includes(details.method)) {
      const hasCSRF = details.requestHeaders.some(header =>
          ["x-csrf-token", "x-requested-with"].includes(header.name.toLowerCase())
      );

    if (!hasCSRF && details.tabId >= 0) {
      console.log("got csrf");
      console.log(`Site ${details.url} .`);
      const warningMessage = `[CSRF ALERT] Insecure CSRF detected: ${details.url}`;
      // get id url
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs.length === 0) return;
        const activeTabId = tabs[0].id;
        const tabUrl = tabs[0].url;
        // immediately inject the inline function to show the popup
        chrome.scripting.executeScript({
          target: { tabId: activeTabId },
          func: (warning, url) => {
            // combine the warning with a prompt message
            const message = warning + "\n\nDo you want to proceed?";
            const userConfirmed = window.confirm(message);
            if (!userConfirmed) {
              chrome.runtime.sendMessage({ action: "block", url: url });
              chrome.runtime.sendMessage({ action: "closeTab" });
            } else {
              console.log(`User chose to proceed with ${url}`);
            }
          },
          args: [warningMessage, tabUrl]
        });
      });
    }
    return;
  }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// ---------------------- Session Cookie Check via onChanged ----------------------

chrome.cookies.onChanged.addListener(function (changeInfo) {
  if (!changeInfo.removed) {
    const cookie = changeInfo.cookie;
    // check if it's a session cookie
    const isSessionCookie = !cookie.expirationDate;
    // check security flags
    const isSecure = cookie.secure;
    const isHttpOnly = cookie.httpOnly;
    console.log("inside cookie onChanged.");
    // if session cookie is insecure
    if (isSessionCookie && (!isSecure || !isHttpOnly)) {
      console.log("insecure session detected.");
      const warningMessage = `[SESSION ALERT] Insecure session cookie detected: ${JSON.stringify(cookie)}`;
      // get id url
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs.length === 0) return;
        const activeTabId = tabs[0].id;
        const tabUrl = tabs[0].url;
        // immediately inject the inline function to show the popup
        chrome.scripting.executeScript({
          target: { tabId: activeTabId },
          func: (warning, url) => {
            // combine the warning with a prompt message
            const message = warning + "\n\nDo you want to proceed?";
            const userConfirmed = window.confirm(message);
            if (!userConfirmed) {
              chrome.runtime.sendMessage({ action: "block", url: url });
              chrome.runtime.sendMessage({ action: "closeTab" });
            } else {
              console.log(`User chose to proceed with ${url}`);
            }
          },
          args: [warningMessage, tabUrl]
        });
      });
    }
    console.log("Cookie set:", cookie);
  }
});

// ---------------------- Message Handling ----------------------
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.action === "block") {
    blockSite(message.url, sender.tab.id);
  } else if (message.action === "closeTab") {
    if (sender.tab && sender.tab.id) {
      chrome.tabs.remove(sender.tab.id);
    }
  }
  else if (message.action === "whitelist") {
    addTemporaryWhitelist(message.url);
  }
  else if (message.action === "checkXSS") {
          const url = message.url;
    
          
          if (!url.includes("?")) {
              sendResponse({ isVulnerable: false, report: [] });
              return;
          }
    
          console.log(`Checking XSS for URL: ${url}`);
    
          const xssPayloadList = [
              `<script>alert('XSS')</script>`,
              `"><script>alert('XSS')</script>`,
              `' onmouseover='alert("XSS")'`,
              `javascript:alert('XSS')`,
              `<img src="x" onerror="alert('XSS')">`
          ];
    
          const parsedUrl = new URL(url);
          const params = parsedUrl.searchParams;
          let vuln = false;
          let detailedReport = [];
    
          for (const [key, value] of params) {
              for (const payload of xssPayloadList) {
                  const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
                  console.log(`Testing: ${testUrl}`);
                  
                  try {
                      const response = await fetch(testUrl);
                      const responseText = await response.text();
    
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
                              response: "Possible XSS vulnerability"
                          });
                          break;
                      }
                  } catch (err) {
                      console.error(`Error testing ${testUrl}:`, err);
                  }
              }
          }
    
          sendResponse({ isVulnerable: vuln, report: detailedReport });
      }
      else if (message.action === "updateFlag") {
        globalFlag = message.flagValue;
        console.log("Flag updated:", globalFlag);
      }
       

});

// "sandbox" download check 
const processedDownloads = new Set();
// a set is used to keep track of processed downloads to avoid duplicate processing

chrome.downloads.onCreated.addListener(async (downloadItem) => {
    console.log("Download started with ID:", downloadItem.id, "URL:", downloadItem.url);
    try{
        //check download by downloadItem.id
        if(processedDownloads.has(downloadItem.id)){
            console.log("Download already processed. Skipping...");
            return;
        }
        //add the downloadItem.id to the set
        processedDownloads.add(downloadItem.id);

        console.log("Download started:", downloadItem);
        //intercepting specific file type - we use zip for now
        if(downloadItem.url && downloadItem.url.endsWith(".zip")) {
            console.log(`zip file detected, perform checking ${downloadItem.url}`);
            //pause the download for analysis
            chrome.downloads.pause(downloadItem.id, async () => {
                if (chrome.runtime.lastError) {
                    console.error("Error pausing download:", chrome.runtime.lastError);
                    return;
                }
                console.log("Download paused for analysis....");
            
                try{
                    //fetch the zip file user trying to download for analysis temporarily
                    // file is blob form in fetchFile()
                    const fileBlob = await fetchFile(downloadItem.url);

                    if (!fileBlob) {
                        console.error("Failed to fetch the file for analysis.");
                        chrome.downloads.cancel(downloadItem.id); // Cancel download if file fetch fails
                        return;
                    }

                    // analyze the zip file
                    // const fileIsSafe = await analyzeZipFile(fileBlob);
                    const {safe: fileIsSafe, filename} = await analyzeZipFile(fileBlob);
                    //analyzeZipFile will check with virustotal function for file hash
                    if(fileIsSafe){
                        //save the file once deemed safe
                        console.log("File is safe, file will be saved....");
                        console.log("the file name is: ", filename);
                        // Cancel the paused original download to prevent conflicts
                        await new Promise((resolve) =>
                            //this is to cancel duplicate download due to pause
                            chrome.downloads.cancel(downloadItem.id, resolve)
                        );
                        //save the file to user disk once is deemed safe
                        await saveFile(fileBlob, filename);
                    }else{
                        console.log("File is not safe, download will be cancelled....");
                        chrome.downloads.cancel(downloadItem.id);
                    }
                }catch (error){
                    console.error("Error fetching file for analysis:", error);
                }
            });
            }
    }catch(error){
        console.error("Error downloading file:", error);
    }
});


// ----------------SQL & XSS check-------------------------------------

// chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
//   console.log("I MANAGED TO GET HERE");
//   if (message.action === "checkXSS") {
//       const url = message.url;

      
//       if (!url.includes("?")) {
//           sendResponse({ isVulnerable: false, report: [] });
//           return;
//       }

//       console.log(`Checking XSS for URL: ${url}`);

//       const xssPayloadList = [
//           `<script>alert('XSS')</script>`,
//           `"><script>alert('XSS')</script>`,
//           `' onmouseover='alert("XSS")'`,
//           `javascript:alert('XSS')`,
//           `<img src="x" onerror="alert('XSS')">`
//       ];

//       const parsedUrl = new URL(url);
//       const params = parsedUrl.searchParams;
//       let vuln = false;
//       let detailedReport = [];

//       for (const [key, value] of params) {
//           for (const payload of xssPayloadList) {
//               const testUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${key}=${encodeURIComponent(payload)}`;
//               console.log(`Testing: ${testUrl}`);
              
//               try {
//                   const response = await fetch(testUrl);
//                   const responseText = await response.text();

//                   if (
//                       responseText.includes("script") ||
//                       responseText.includes("alert") ||
//                       responseText.includes("onerror") ||
//                       responseText.includes("onload")
//                   ) {
//                       vuln = true;
//                       detailedReport.push({
//                           parameter: key,
//                           payload,
//                           response: "Possible XSS vulnerability"
//                       });
//                       break;
//                   }
//               } catch (err) {
//                   console.error(`Error testing ${testUrl}:`, err);
//               }
//           }
//       }

//       sendResponse({ isVulnerable: vuln, report: detailedReport });
//   }
//   return true; 
// });
