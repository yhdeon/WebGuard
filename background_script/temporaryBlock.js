import { extractMainDomain } from './extraMainURL.js';

const blockDuration = 1 * 60 * 1000; // 1 minute

export function clearExpiredBlockedSites() {
    chrome.storage.local.get(["blockedSites"], (data) => {
      let blockedSites = data.blockedSites || {};
      const now = Date.now();
      let updatedSites = {};
  
      Object.keys(blockedSites).forEach((site) => {
        const blockTime = blockedSites[site];
        if (now - blockTime < blockDuration) {
          updatedSites[site] = blockTime; // Keep unexpired blocks
        } else {
          console.log(`Unblocking site: ${site} (Blocked for ${((now - blockTime) / 1000).toFixed(1)} sec)`);
        }
      });
  
      chrome.storage.local.set({ blockedSites: updatedSites }, () => {
        console.log(" Expired blocked sites removed.");
        updateBlockRules();
      });
    });
  }

export async function blockSite(url, tabId) {
    const mainDomain = extractMainDomain(url);
    if (!mainDomain) return;
    chrome.storage.local.get(["blockedSites"], (data) => {
      let blockedSites = data.blockedSites || {};
      blockedSites[mainDomain] = Date.now();
      chrome.storage.local.set({ blockedSites }, () => {
        console.log(`Blocked ${mainDomain} for ${blockDuration / 60000} minute(s).`);
        updateBlockRules();
        if (tabId) {
          chrome.tabs.remove(tabId); // Close the tab
        }
      });
    });
  }
  
  export  async function isBlocked(url) {
    const mainDomain = extractMainDomain(url);
    return new Promise((resolve) => {
      chrome.storage.local.get(["blockedSites"], (data) => {
        const blockedSites = data.blockedSites || {};
        resolve(blockedSites[mainDomain] && Date.now() - blockedSites[mainDomain] < BLOCK_DURATION);
      });
    });
  }
  
  export async function updateBlockRules() {
    chrome.declarativeNetRequest.getDynamicRules((rules) => {
      const existingRuleIds = rules.map(rule => rule.id);
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingRuleIds,
        addRules: []
      }, () => {
        console.log(`Cleared previous blocking rules.`);
        chrome.storage.local.get(["blockedSites"], (data) => {
          let blockedSites = data.blockedSites || {};
          let newRules = Object.keys(blockedSites).map((site, index) => ({
            id: index + 1,
            priority: 1,
            action: { type: "block" },
            condition: { urlFilter: site, resourceTypes: ["main_frame"] }
          }));
          chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [],
            addRules: newRules
          }, () => {
            console.log(`Updated blocking rules. Active blocked sites: ${Object.keys(blockedSites).length}`);
          });
        });
      });
    });
  }