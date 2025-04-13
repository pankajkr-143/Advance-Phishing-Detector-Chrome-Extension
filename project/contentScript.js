// Content script to analyze page content and send results to background script
(function() {
  // Analyze page content when loaded
  document.addEventListener('DOMContentLoaded', analyzeContent);

  async function analyzeContent() {
    const features = extractPageFeatures();
    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS',
      data: features
    });

    const risk = calculateRisk(features);
    if (risk > 0.25 && !isTrustedDomain(window.location.hostname)) {
      showWarningPopup(risk);
    }
  }

  function isTrustedDomain(hostname) {
    const trustedDomains = new Set([
      'hdfcbank.com', 'icicibank.com', 'onlinesbi.sbi', 'axisbank.com', 'kotak.com',
      'bankofbaroda.in', 'sbi.co.in', 'pnbindia.in', 'google.com', 'wikipedia.org',
      'duckduckgo.com', 'bing.com', 'google.co.in', 'bbc.com', 'theguardian.com',
      'nytimes.com', 'reuters.com', 'apnews.com', 'timesofindia.indiatimes.com',
      'thehindu.com', 'indianexpress.com', 'ndtv.com', 'news18.com', 'amazon.in',
      'flipkart.com', 'myntra.com', 'ajio.com', 'nykaa.com', 'jiomart.com',
      'tatacliq.com', 'snapdeal.com', 'meesho.com', 'indiamart.com'
    ]);
    
    const baseDomain = hostname.replace(/^www\./, '');
    return trustedDomains.has(baseDomain);
  }

  function extractPageFeatures() {
    return {
      hasLoginForm: !!document.querySelector('form input[type="password"]'),
      hasHttpsForm: Array.from(document.forms).some(form => 
        form.action && form.action.startsWith('https://')),
      externalLinks: countExternalLinks(),
      hasIframe: !!document.querySelector('iframe'),
      hasFavicon: !!document.querySelector('link[rel="icon"]'),
      hasPopups: !!document.querySelector('[role="dialog"]'),
      hasHiddenElements: document.querySelectorAll('[style*="display: none"]').length,
      hasAbnormalContent: checkAbnormalContent(),
      hasSuspiciousScripts: checkSuspiciousScripts(),
      hasDataCollection: checkDataCollection()
    };
  }

  function checkAbnormalContent() {
    const suspiciousElements = [
      'input[type="password"]',
      'input[name*="card"]',
      'input[name*="cvv"]',
      'input[name*="ssn"]',
      'input[name*="social"]'
    ];
    return suspiciousElements.some(selector => document.querySelector(selector));
  }

  function checkSuspiciousScripts() {
    const scripts = document.getElementsByTagName('script');
    const suspiciousPatterns = [
      'eval(',
      'document.write(',
      'window.location',
      'localStorage',
      'sessionStorage'
    ];
    
    return Array.from(scripts).some(script => 
      suspiciousPatterns.some(pattern => script.textContent?.includes(pattern))
    );
  }

  function checkDataCollection() {
    return document.querySelectorAll('form').length > 2;
  }

  function countExternalLinks() {
    const currentDomain = window.location.hostname;
    return Array.from(document.links).filter(link => 
      link.hostname && link.hostname !== currentDomain
    ).length;
  }

  function calculateRisk(features) {
    let risk = 0;
    
    // Core security checks
    if (features.hasLoginForm && !features.hasHttpsForm) risk += 0.4;
    if (features.hasIframe) risk += 0.2;
    if (!features.hasFavicon) risk += 0.1;
    if (features.hasPopups) risk += 0.2;
    if (features.hasHiddenElements > 5) risk += 0.3;
    if (features.externalLinks > 20) risk += 0.2;
    
    // Additional security checks
    if (features.hasAbnormalContent) risk += 0.3;
    if (features.hasSuspiciousScripts) risk += 0.25;
    if (features.hasDataCollection) risk += 0.15;
    
    return Math.min(1, risk);
  }

  function showWarningPopup(risk) {
    const popup = document.createElement('div');
    
    // Customize warning based on risk level
    let warningMessage = '🚨 Warning: ';
    if (risk > 0.7) {
      warningMessage += 'High-risk phishing website detected! Leave immediately!';
    } else if (risk > 0.4) {
      warningMessage += 'This site shows signs of being a phishing website. Proceed with caution!';
    } else {
      warningMessage += 'This site may be a phishing website. Be careful!';
    }
    
    popup.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${risk > 0.7 ? '#ff4444' : risk > 0.4 ? '#ff8800' : '#ffaa00'};
      color: white;
      padding: 15px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      animation: slideIn 0.5s ease-out;
      max-width: 400px;
      line-height: 1.5;
    `;
    
    popup.innerHTML = warningMessage;
    document.body.appendChild(popup);

    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);

    setTimeout(() => {
      popup.style.animation = 'slideOut 0.5s ease-in';
      popup.addEventListener('animationend', () => popup.remove());
    }, 5000);
  }
})();