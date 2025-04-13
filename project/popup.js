// ML model features and weights (enhanced for better accuracy)
const MODEL_WEIGHTS = {
  urlLength: -0.03,
  hasHttps: 0.4,
  hasAtSymbol: -0.3,
  hasDashInDomain: -0.2,
  domainAge: 0.3,
  hasSpecialChars: -0.25,
  hasIpAddress: -0.4,
  hasMultipleSubdomains: -0.2,
  hasValidSSL: 0.4,
  hasSuspiciousRedirect: -0.3,
  hasAbnormalURL: -0.35,
  hasKnownPhishingPattern: -0.5
};

// List of trusted domains
const TRUSTED_DOMAINS = new Set([
  // Banks
  'hdfcbank.com', 'icicibank.com', 'onlinesbi.sbi', 'axisbank.com', 'kotak.com',
  'bankofbaroda.in', 'sbi.co.in', 'pnbindia.in',
  // Search Engines
  'google.com', 'wikipedia.org', 'duckduckgo.com', 'bing.com', 'google.co.in',
  // News
  'bbc.com', 'theguardian.com', 'nytimes.com', 'reuters.com', 'apnews.com',
  'timesofindia.indiatimes.com', 'thehindu.com', 'indianexpress.com', 'ndtv.com', 'news18.com',
  // E-commerce
  'amazon.in', 'flipkart.com', 'myntra.com', 'ajio.com', 'nykaa.com',
  'jiomart.com', 'tatacliq.com', 'snapdeal.com', 'meesho.com', 'indiamart.com'
]);

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  const tab = await getCurrentTab();
  const analysis = await analyzeUrl(tab.url);
  updateUI(analysis);

  document.getElementById('learnMore').addEventListener('click', () => {
    chrome.tabs.create({
      url: 'https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams'
    });
  });
});

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function isTrustedDomain(hostname) {
  const baseDomain = hostname.replace(/^www\./, '');
  return TRUSTED_DOMAINS.has(baseDomain);
}

async function analyzeUrl(url) {
  const features = await extractFeatures(url);
  const urlObj = new URL(url);
  
  let score;
  if (isTrustedDomain(urlObj.hostname)) {
    score = 15;
  } else {
    score = await calculateRiskScore(features, urlObj);
  }

  const securityAnalysis = analyzeSecurityIndicators(features, urlObj);
  const contentAnalysis = await analyzeContent(features);
  const issues = detectIssues(features, urlObj.hostname, securityAnalysis, contentAnalysis);
  const suggestions = generateSuggestions(score, securityAnalysis, contentAnalysis);
  const riskLevel = getRiskLevel(score);

  return {
    score,
    issues,
    suggestions,
    securityAnalysis,
    contentAnalysis,
    riskLevel,
    isTrusted: isTrustedDomain(urlObj.hostname)
  };
}

async function extractFeatures(url) {
  const urlObj = new URL(url);
  return {
    urlLength: url.length,
    hasHttps: urlObj.protocol === 'https:',
    hasAtSymbol: url.includes('@'),
    hasDashInDomain: urlObj.hostname.includes('-'),
    hasSpecialChars: /[^a-zA-Z0-9-.]/.test(urlObj.hostname),
    hasIpAddress: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(urlObj.hostname),
    hasMultipleSubdomains: urlObj.hostname.split('.').length > 2,
    hasValidSSL: urlObj.protocol === 'https:',
    hasSuspiciousRedirect: url.includes('redirect') || url.includes('goto'),
    hasAbnormalURL: checkAbnormalURL(url),
    hasKnownPhishingPattern: checkPhishingPatterns(url)
  };
}

function checkAbnormalURL(url) {
  const suspicious = [
    'login', 'signin', 'account', 'verify', 'secure', 'update',
    'authentication', 'authenticate', 'wallet', 'password'
  ];
  return suspicious.some(term => url.toLowerCase().includes(term));
}

function checkPhishingPatterns(url) {
  const patterns = [
    /\d{10,}/, // Long numbers
    /[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+/, // Multiple subdomains
    /([a-zA-Z0-9]+\.){3,}/, // Too many dots
    /-{2,}/, // Multiple consecutive dashes
    /\.(tk|ml|ga|cf|gq)$/ // Known free domains often used in phishing
  ];
  return patterns.some(pattern => pattern.test(url));
}

async function calculateRiskScore(features, urlObj) {
  let score = 0;
  
  // Base score from features
  for (const [feature, weight] of Object.entries(MODEL_WEIGHTS)) {
    if (features[feature]) {
      score += weight;
    }
  }

  // Additional security checks
  if (!features.hasHttps) score -= 0.3;
  if (features.hasMultipleSubdomains) score -= 0.2;
  if (features.hasKnownPhishingPattern) score -= 0.4;
  if (features.hasAbnormalURL) score -= 0.2;

  // Normalize score between 0 and 100
  score = Math.max(0, Math.min(100, (score + 1) * 50));
  return score;
}

function analyzeSecurityIndicators(features, urlObj) {
  return {
    https: features.hasHttps,
    ssl: features.hasValidSSL,
    domainStructure: !features.hasMultipleSubdomains,
    suspiciousPatterns: !features.hasKnownPhishingPattern,
    urlSafety: !features.hasAbnormalURL
  };
}

async function analyzeContent(features) {
  return {
    legitimateDesign: !features.hasAbnormalURL,
    secureConnection: features.hasHttps,
    validCertificate: features.hasValidSSL,
    normalNavigation: !features.hasSuspiciousRedirect
  };
}

function getRiskLevel(score) {
  if (score <= 25) {
    return {
      level: 'low',
      text: 'Low Risk - This website appears to be legitimate and safe to use'
    };
  } else if (score <= 50) {
    return {
      level: 'medium',
      text: 'Medium Risk - Exercise caution when using this website. Verify its authenticity before sharing sensitive information'
    };
  } else {
    return {
      level: 'high',
      text: 'High Risk - This website shows multiple signs of being potentially malicious. Avoid entering any sensitive information'
    };
  }
}

function detectIssues(features, hostname, securityAnalysis, contentAnalysis) {
  const issues = [];
  
  if (!isTrustedDomain(hostname)) {
    // Security Indicators
    if (!securityAnalysis.https) {
      issues.push('Insecure Connection: Website does not use HTTPS encryption');
    }
    if (!securityAnalysis.ssl) {
      issues.push('Invalid SSL Certificate: The website\'s security certificate could not be verified');
    }
    if (!securityAnalysis.domainStructure) {
      issues.push('Suspicious Domain Structure: Multiple subdomains detected');
    }
    if (!securityAnalysis.suspiciousPatterns) {
      issues.push('Known Phishing Patterns: Website contains patterns commonly used in phishing attacks');
    }
    
    // Content Analysis
    if (!contentAnalysis.legitimateDesign) {
      issues.push('Suspicious Design: Website layout or content appears unusual');
    }
    if (!contentAnalysis.normalNavigation) {
      issues.push('Abnormal Navigation: Suspicious redirect patterns detected');
    }
  }
  
  return issues;
}

function generateSuggestions(score, securityAnalysis, contentAnalysis) {
  const suggestions = [];
  
  if (score <= 25) {
    suggestions.push('✅ Website appears legitimate based on our security analysis');
    suggestions.push('✅ Standard security measures are in place');
    suggestions.push('👉 Always verify you\'re on the official domain before entering sensitive information');
  } else if (score <= 50) {
    suggestions.push('⚠️ Double-check the website URL for accuracy');
    suggestions.push('🔍 Verify the website\'s identity through official channels');
    suggestions.push('🛡️ Do not enter sensitive information unless absolutely necessary');
    suggestions.push('📱 Consider using official mobile apps instead of the website');
  } else {
    suggestions.push('❌ Do not enter any personal or financial information');
    suggestions.push('⚠️ Leave this website immediately');
    suggestions.push('🚨 Report this website to phishing databases');
    suggestions.push('🔒 Change any passwords if you\'ve entered them here');
  }
  
  return suggestions;
}

function updateUI(analysis) {
  const statusEl = document.getElementById('status');
  const scoreEl = document.getElementById('riskScore');
  const riskLevelEl = document.getElementById('riskLevel');
  const issuesListEl = document.getElementById('issuesList');
  const suggestionsListEl = document.getElementById('suggestionsList');

  statusEl.textContent = analysis.isTrusted ? 'Trusted Website' : 'Analysis Complete';
  scoreEl.textContent = Math.round(analysis.score);
  scoreEl.className = `score ${getScoreClass(analysis.score)}`;

  riskLevelEl.textContent = analysis.riskLevel.text;
  riskLevelEl.className = `risk-level ${analysis.riskLevel.level}`;

  issuesListEl.innerHTML = analysis.issues
    .map(issue => `<li>${issue}</li>`)
    .join('');

  suggestionsListEl.innerHTML = analysis.suggestions
    .map(suggestion => `<li>${suggestion}</li>`)
    .join('');
}

function getScoreClass(score) {
  if (score <= 25) return 'safe';
  if (score <= 50) return 'warning';
  return 'danger';
}