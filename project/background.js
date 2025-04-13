// Background service worker for persistent analysis
let pageAnalysis = {};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PAGE_ANALYSIS') {
    const tabId = sender.tab.id;
    pageAnalysis[tabId] = message.data;
    updateBadge(tabId, calculateRisk(message.data));
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete pageAnalysis[tabId];
});

function calculateRisk(features) {
  // Simple risk calculation based on page features
  let risk = 0;
  if (features.hasLoginForm && !features.hasHttpsForm) risk += 0.4;
  if (features.hasIframe) risk += 0.2;
  if (!features.hasFavicon) risk += 0.1;
  if (features.hasPopups) risk += 0.2;
  if (features.hasHiddenElements > 5) risk += 0.3;
  if (features.externalLinks > 20) risk += 0.2;
  return Math.min(1, risk);
}

function updateBadge(tabId, risk) {
  const color = risk > 0.7 ? '#f44336' : risk > 0.4 ? '#ff9800' : '#4caf50';
  const text = Math.round(risk * 100).toString();
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}