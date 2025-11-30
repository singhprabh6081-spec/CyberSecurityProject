document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scan-button');
    const resultsContainer = document.getElementById('results-container');
    const placeholder = document.getElementById('placeholder');

    // Function to render results in the popup
    function renderResults(results) {
        resultsContainer.innerHTML = ''; // Clear previous results
        if (!results || results.length === 0) {
            placeholder.textContent = 'No vulnerabilities found or scan not run yet.';
            resultsContainer.appendChild(placeholder);
            return;
        }

        results.forEach(result => {
            const resultElement = document.createElement('div');
            // Use the new local CSS classes
            resultElement.className = `result-item severity-${result.severity.toLowerCase()}`;
            
            resultElement.innerHTML = `
                <h3>${result.title}</h3>
                <p>${result.description}</p>
                <p class="severity-label">Severity: <span>${result.severity}</span></p>
            `;
            resultsContainer.appendChild(resultElement);
        });
    }

    // Event listener for the scan button
    scanButton.addEventListener('click', () => {
        scanButton.disabled = true;
        scanButton.textContent = 'Scanning...';
        placeholder.textContent = 'Analyzing page...';

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length === 0) {
                console.error("No active tab found.");
                scanButton.disabled = false;
                scanButton.textContent = 'Scan Current Page';
                return;
            }
            const tabId = tabs[0].id;

            chrome.runtime.sendMessage({ type: 'SCAN_PAGE', tabId: tabId }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error('Error sending message:', chrome.runtime.lastError.message);
                    placeholder.textContent = 'Error: Could not connect to scanner.';
                    renderResults([]);
                } else {
                    console.log("Scan results received from background:", response);
                    renderResults(response.results);
                }
                scanButton.disabled = false;
                scanButton.textContent = 'Scan Current Page';
            });
        });
    });

    // Load and display previous results when popup is opened
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            const url = tabs[0].url;
            chrome.storage.local.get([url], (data) => {
                if (data[url]) {
                    renderResults(data[url]);
                }
            });
        }
    });
});