const headerCache = {};

// Listener for network requests to capture security headers
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        // Store headers for the main frame document
        if (details.type === 'main_frame') {
            headerCache[details.tabId] = details.responseHeaders;
        }
    },
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders"]
);

// Listener for messages from the popup script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'SCAN_PAGE') {
        const tabId = request.tabId;
        performScan(tabId)
            .then(results => {
                sendResponse({ results });
                // Store results for the specific URL
                chrome.tabs.get(tabId, tab => {
                    if (tab.url) {
                        chrome.storage.local.set({ [tab.url]: results });
                    }
                });
            })
            .catch(error => {
                console.error("Scan failed:", error);
                sendResponse({ results: [{ title: "Scan Error", description: "Could not complete the scan.", severity: "High" }] });
            });
        return true; // Indicates that the response is sent asynchronously
    }
});

// Main scan function
async function performScan(tabId) {
    const headers = headerCache[tabId] || [];
    let results = [];

    // 1. Analyze Security Headers
    results.push(...checkSecurityHeaders(headers));

    // 2. Execute content script checks (forms, libraries, cookies)
    try {
        const contentScriptResults = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            function: runContentScriptChecks,
        });
        if (contentScriptResults && contentScriptResults.length > 0) {
            results.push(...contentScriptResults[0].result);
        }
    } catch (e) {
        console.error("Failed to execute content script:", e);
        results.push({ title: "Content Script Error", description: "Could not analyze the page's content. The page might be protected.", severity: "Info" });
    }
    
    return results;
}

// Function to check for key security headers
function checkSecurityHeaders(headers) {
    const findings = [];
    const headerNames = headers.map(h => h.name.toLowerCase());

    // Check for Content-Security-Policy
    if (!headerNames.includes('content-security-policy')) {
        findings.push({ title: 'Content-Security-Policy (CSP) Missing', description: 'CSP helps prevent XSS and other injection attacks. It should be implemented.', severity: 'Medium' });
    }

    // Check for Strict-Transport-Security (HSTS)
    if (!headerNames.includes('strict-transport-security')) {
        findings.push({ title: 'Strict-Transport-Security (HSTS) Missing', description: 'HSTS enforces secure (HTTPS) connections to the server.', severity: 'Medium' });
    }

    // Check for X-Content-Type-Options
    if (!headerNames.includes('x-content-type-options')) {
        findings.push({ title: 'X-Content-Type-Options Missing', description: 'This header prevents the browser from MIME-sniffing a response away from the declared content-type.', severity: 'Low' });
    } else {
        const header = headers.find(h => h.name.toLowerCase() === 'x-content-type-options');
        if (header.value.toLowerCase() !== 'nosniff') {
            findings.push({ title: 'X-Content-Type-Options Misconfigured', description: `Header should be set to 'nosniff', but is '${header.value}'.`, severity: 'Low' });
        }
    }
    
    // Check for X-Frame-Options (Clickjacking)
    if (!headerNames.includes('x-frame-options') && !headerNames.includes('content-security-policy')) {
         findings.push({ title: 'Clickjacking Protection Missing', description: 'Use X-Frame-Options or a CSP frame-ancestors directive to prevent clickjacking attacks.', severity: 'High' });
    }

    return findings;
}

// This function will be injected into the page to run checks
function runContentScriptChecks() {
    const findings = [];

    // 3. Check for insecure forms
    document.querySelectorAll('form').forEach(form => {
        if (form.action.startsWith('http://')) {
            findings.push({ title: 'Insecure Form Submission', description: `A form on this page submits data to an insecure HTTP URL: ${form.action}`, severity: 'High' });
        }
    });

    // 4. Check cookie security
    const cookies = document.cookie.split(';');
    if (document.cookie) { // Only check if cookies exist
        document.querySelectorAll('a').forEach(el => { // Dummy check to show concept
            // In a real scenario, this is limited. Background script is better for HttpOnly.
            // This is a simplified check.
        });
        if (window.location.protocol === 'https:') {
            // A truly robust cookie check requires observing Set-Cookie headers in the background script.
            // This is a simplified representation.
             findings.push({ title: 'Cookie Security', description: 'Review cookies to ensure `Secure` and `HttpOnly` flags are used appropriately. This check is informational as content scripts have limited access.', severity: 'Info' });
        }
    }

    // 5. Check for vulnerable JS libraries (simplified example)
    const scripts = Array.from(document.querySelectorAll('script'));
    const jqueryScript = scripts.find(s => s.src.includes('jquery-'));
    if (jqueryScript) {
        const match = jqueryScript.src.match(/jquery-([\d\.]+)\.js/);
        if (match) {
            const version = match[1];
            // In a real extension, you'd compare this against a list of vulnerable versions.
            if (version.startsWith('1.') || version.startsWith('2.')) {
                 findings.push({ title: 'Potentially Vulnerable jQuery', description: `The site uses jQuery version ${version}, which may have known vulnerabilities.`, severity: 'Medium' });
            }
        }
    }
    
    return findings;
}