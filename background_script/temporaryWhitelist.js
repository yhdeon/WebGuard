import { extractMainDomain } from './extraMainURL.js';

const whiteListDuration = 1 * 60 * 1000; // 1 minute

export async function addTemporaryWhitelist(url) {
    const mainDomain = extractMainDomain(url);
    if (!mainDomain) return;
  
    chrome.storage.local.get(["whitelistedSites"], (data) => {
      let whitelistedSites = data.whitelistedSites || {};
      whitelistedSites[mainDomain] = Date.now(); // Store timestamp
      chrome.storage.local.set({ whitelistedSites }, () => {
        console.log(`Temporarily whitelisted ${mainDomain} for 1 minute.`);
      });
    });
  }
  
  // Function to check if a site is temporarily whitelisted
  export async function isTemporarilyWhitelisted(url) {
    const mainDomain = extractMainDomain(url);
    if (!mainDomain) return false;
  
    return new Promise((resolve) => {
      chrome.storage.local.get(["whitelistedSites"], (data) => {
        const whitelistedSites = data.whitelistedSites || {};
        const expiryTime = whitelistedSites[mainDomain];
  
        resolve(expiryTime && Date.now() - expiryTime < whiteListDuration);
      });
    });
  }
  
  // Function to remove expired whitelisted sites
  export function clearExpiredWhitelistedSites() {
    chrome.storage.local.get(["whitelistedSites"], (data) => {
      let whitelistedSites = data.whitelistedSites || {};
      const now = Date.now();
      let updatedSites = {};
  
      Object.keys(whitelistedSites).forEach((site) => {
        const whitelistTime = whitelistedSites[site];
        if (now - whitelistTime < whiteListDuration) {
          updatedSites[site] = whitelistTime; // Keep unexpired sites
        } else {
          console.log(` Removing expired whitelist: ${site} (Whitelisted for ${((now - whitelistTime) / 1000).toFixed(1)} sec)`);
        }
      });
  
      chrome.storage.local.set({ whitelistedSites: updatedSites }, () => {
        console.log(" Expired temporary whitelisted sites removed.");
      });
    });
  }