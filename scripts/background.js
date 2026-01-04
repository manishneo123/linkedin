// Background service worker
// Currently not heavily used, but good for persistence later.

chrome.runtime.onInstalled.addListener(() => {
    console.log('LinkedIn Sales Copilot installed');
});

// Open side panel when extension icon is clicked
chrome.action.onClicked.addListener(async (tab) => {
    // Only open side panel on LinkedIn pages
    if (tab.url && (tab.url.includes('linkedin.com'))) {
        try {
            await chrome.sidePanel.open({ tabId: tab.id });
        } catch (e) {
            console.error('Error opening side panel:', e);
            // Fallback: open as popup if side panel not available
            chrome.action.setPopup({ popup: 'popup/popup.html' });
        }
    }
});

// Set side panel for LinkedIn tabs automatically
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
    if (tab.url && tab.url.includes('linkedin.com')) {
        if (info.status === 'complete') {
            try {
                await chrome.sidePanel.setOptions({
                    tabId: tabId,
                    path: 'popup/popup.html',
                    enabled: true
                });
            } catch (e) {
                console.log('Side panel API not available:', e);
            }
        }
    }
});
