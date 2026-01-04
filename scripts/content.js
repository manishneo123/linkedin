chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'PING') {
        sendResponse({ success: true, message: 'PONG' });
        return true;
    }

    if (request.action === 'SCRAPE_PROFILE') {
        console.log('[ContentScript] 🚀 Starting enhanced profile extraction...');

        try {
            // Extract main profile text
            const mainContent = document.querySelector('main') || document.querySelector('.scaffold-layout__main') || document.body;
            let profileText = mainContent.innerText || '';
            profileText = profileText.replace(/\s+/g, ' ').trim().substring(0, 40000);

            console.log('[ContentScript] ✓ Profile text extracted:', profileText.length, 'chars');

            // Extract recent activity (posts, likes, comments)
            const activity = extractRecentActivity();
            console.log('[ContentScript] ✓ Activity extracted:', activity.posts.length, 'posts,', activity.likes.length, 'likes');

            // Extract company info for job scraping
            const companyInfo = extractCompanyInfo();
            console.log('[ContentScript] ✓ Company info:', companyInfo.name || 'Not found');

            // Extract related profiles (People also viewed, People you may know)
            const relatedProfiles = extractRelatedProfiles();
            console.log('[ContentScript] ✓ Related profiles:', relatedProfiles.length, 'found');

            sendResponse({
                success: true,
                data: profileText,
                activity: activity,
                company: companyInfo,
                relatedProfiles: relatedProfiles
            });
        } catch (e) {
            console.error('[ContentScript] ✗ Error during scraping:', e);
            sendResponse({ success: false, error: e.message });
        }
        return true;
    }

    if (request.action === 'FETCH_POST_CONTENT') {
        console.log('[ContentScript] 📥 Fetching post content from URL:', request.url);
        
        (async () => {
            try {
                const postContent = await fetchPostContent(request.url);
                sendResponse({ success: true, content: postContent });
            } catch (e) {
                console.error('[ContentScript] ✗ Error fetching post:', e);
                sendResponse({ success: false, error: e.message });
            }
        })();
        
        return true; // Keep channel open for async response
    }

    if (request.action === 'LOAD_RECENT_ACTIVITY') {
        console.log('[ContentScript] 📋 Loading recent activity page...');
        
        (async () => {
            try {
                const activity = await loadRecentActivityPage();
                sendResponse({ success: true, activity: activity });
            } catch (e) {
                console.error('[ContentScript] ✗ Error loading recent activity:', e);
                sendResponse({ success: false, error: e.message });
            }
        })();
        
        return true; // Keep channel open for async response
    }

    return true; // Keep channel open for async response
});

/**
 * Extract recent activity from LinkedIn profile
 */
function extractRecentActivity() {
    console.log('[Activity] Starting activity extraction...');

    const activity = {
        posts: [],
        likes: [],
        comments: []
    };

    // Look for activity feed section
    const activitySection = document.querySelector('[data-view-name="profile-recent-activity"]') ||
        document.querySelector('.pv-recent-activity-section');

    if (!activitySection) {
        console.log('[Activity] ⚠ Activity section not found');
        return activity;
    }

    console.log('[Activity] Found activity section, extracting items...');

    // Extract post items
    const activityItems = activitySection.querySelectorAll('.feed-shared-update-v2, .profile-creator-shared-feed-update__container');

    console.log('[Activity] Found', activityItems.length, 'activity items');

    activityItems.forEach((item, index) => {
        if (index >= 10) return; // Limit to 10 most recent for better coverage

        try {
            const text = item.querySelector('.feed-shared-text, .update-components-text')?.innerText?.trim();
            const type = item.querySelector('.feed-shared-actor__description, .update-components-actor__description')?.innerText?.trim();
            
            // Try to find post URL
            let postUrl = null;
            const linkElement = item.querySelector('a[href*="/feed/update/"], a[href*="/activity-"], a[href*="/posts/"]');
            if (linkElement) {
                postUrl = linkElement.href;
            }
            
            // Try to get full text (expand "see more" if present)
            let fullText = text || '';
            const seeMoreBtn = item.querySelector('button[aria-label*="see more"], .feed-shared-text__see-more');
            if (seeMoreBtn && !seeMoreBtn.classList.contains('expanded')) {
                try {
                    seeMoreBtn.click();
                    // Wait a bit for content to expand
                    setTimeout(() => {
                        const expandedText = item.querySelector('.feed-shared-text, .update-components-text')?.innerText?.trim();
                        if (expandedText && expandedText.length > fullText.length) {
                            fullText = expandedText;
                        }
                    }, 200);
                } catch (e) {
                    console.log('[Activity] Could not expand post', index);
                }
            }

            if (fullText) {
                const activityEntry = {
                    text: fullText.substring(0, 2000), // Increased limit for better context
                    fullText: fullText, // Keep full text
                    type: type || 'post',
                    preview: fullText.substring(0, 100) + '...',
                    url: postUrl,
                    timestamp: item.querySelector('time')?.getAttribute('datetime') || null
                };

                // Categorize by type
                if (type?.toLowerCase().includes('like')) {
                    activity.likes.push(activityEntry);
                } else if (type?.toLowerCase().includes('comment')) {
                    activity.comments.push(activityEntry);
                } else {
                    activity.posts.push(activityEntry);
                }

                console.log('[Activity]  →', activityEntry.type, ':', activityEntry.preview);
            }
        } catch (err) {
            console.log('[Activity] ⚠ Error parsing item', index, ':', err.message);
        }
    });

    console.log('[Activity] ✓ Extracted:', activity.posts.length, 'posts,', activity.likes.length, 'likes,', activity.comments.length, 'comments');

    return activity;
}

/**
 * Extract company information from profile
 */
function extractCompanyInfo() {
    console.log('[Company] Extracting company info...');

    const company = {
        name: '',
        url: '',
        linkedinUrl: ''
    };

    // Try to find current company from experience section
    const experienceSection = document.querySelector('#experience')?.parentElement;
    if (experienceSection) {
        const firstExperience = experienceSection.querySelector('li.artdeco-list__item');
        if (firstExperience) {
            const companyLink = firstExperience.querySelector('a[href*="/company/"]');
            if (companyLink) {
                company.name = companyLink.innerText?.trim() || '';
                company.linkedinUrl = companyLink.href;
                console.log('[Company] ✓ Found company:', company.name);
                console.log('[Company]   LinkedIn URL:', company.linkedinUrl);
            }
        }
    }

    // Alternative: try from profile header
    if (!company.name) {
        const headerCompany = document.querySelector('.pv-text-details__right-panel a[href*="/company/"]');
        if (headerCompany) {
            company.name = headerCompany.innerText?.trim() || '';
            company.linkedinUrl = headerCompany.href;
            console.log('[Company] ✓ Found company (from header):', company.name);
        }
    }

    if (!company.name) {
        console.log('[Company] ⚠ Company not found');
    }

    return company;
}

/**
 * Extract related profiles from "People also viewed" and "People you may know" sections
 */
function extractRelatedProfiles() {
    console.log('[RelatedProfiles] Starting extraction...');
    
    const profiles = [];
    
    // Look for "People also viewed" section
    const alsoViewedSection = document.querySelector('[data-view-name="profile-people-also-viewed-card"], .people-also-viewed, [data-test-id="people-also-viewed"]');
    
    // Look for "People you may know" section
    const mayKnowSection = document.querySelector('[data-view-name="profile-people-you-may-know-card"], .people-you-may-know, [data-test-id="people-you-may-know"]');
    
    // Try alternative selectors
    const sections = [
        alsoViewedSection,
        mayKnowSection,
        document.querySelector('.pvs-list__container'),
        document.querySelector('[data-view-name="profile-people-also-viewed"]'),
        document.querySelector('[data-view-name="profile-people-you-may-know"]')
    ].filter(Boolean);
    
    // Also try finding by text content
    const allSections = document.querySelectorAll('section, div[class*="people"], div[class*="viewed"]');
    allSections.forEach(section => {
        const text = section.innerText || '';
        if (text.includes('People also viewed') || text.includes('People you may know') || text.includes('You may know')) {
            sections.push(section);
        }
    });
    
    console.log(`[RelatedProfiles] Found ${sections.length} potential sections`);
    
    sections.forEach((section, sectionIndex) => {
        // Find profile cards/items
        const profileItems = section.querySelectorAll('li, .pvs-list__item, .entity-result, [data-test-id="people-also-viewed-item"], [data-test-id="people-you-may-know-item"]');
        
        console.log(`[RelatedProfiles] Section ${sectionIndex + 1}: Found ${profileItems.length} items`);
        
        profileItems.forEach((item, index) => {
            if (index >= 10) return; // Limit to 10 per section
            
            try {
                // Extract name
                const nameElement = item.querySelector('.entity-result__title-text a, .pvs-entity__sub-title a, a[href*="/in/"]');
                const name = nameElement?.innerText?.trim() || '';
                
                // Extract profile URL
                let profileUrl = null;
                if (nameElement && nameElement.href) {
                    profileUrl = nameElement.href.split('?')[0]; // Remove query params
                } else {
                    const linkElement = item.querySelector('a[href*="/in/"]');
                    if (linkElement) {
                        profileUrl = linkElement.href.split('?')[0];
                    }
                }
                
                // Extract headline
                const headlineElement = item.querySelector('.entity-result__primary-subtitle, .pvs-entity__caption, .entity-result__summary');
                const headline = headlineElement?.innerText?.trim() || '';
                
                // Extract location (optional)
                const locationElement = item.querySelector('.entity-result__secondary-subtitle, .pvs-entity__sub-title');
                const location = locationElement?.innerText?.trim() || '';
                
                if (name && profileUrl && profileUrl.includes('/in/')) {
                    // Avoid duplicates
                    if (!profiles.some(p => p.url === profileUrl)) {
                        profiles.push({
                            name: name,
                            url: profileUrl,
                            headline: headline,
                            location: location
                        });
                        console.log(`[RelatedProfiles] ✓ Extracted: ${name} - ${headline.substring(0, 50)}`);
                    }
                }
            } catch (err) {
                console.log(`[RelatedProfiles] ⚠ Error parsing item ${index}:`, err.message);
            }
        });
    });
    
    console.log(`[RelatedProfiles] ✓ Extracted ${profiles.length} unique profiles`);
    return profiles;
}

/**
 * Fetch post content from a LinkedIn post URL
 * Note: This tries to extract content from the current page if the post is visible
 * For better results, the post should be loaded in the current tab
 */
async function fetchPostContent(postUrl) {
    console.log('[PostFetch] Attempting to fetch content from:', postUrl);
    
    try {
        const postContent = {
            text: '',
            author: '',
            timestamp: '',
            engagement: {
                likes: 0,
                comments: 0,
                shares: 0
            }
        };
        
        // Check if we're already on a post page
        const currentUrl = window.location.href;
        const isPostPage = currentUrl.includes('/feed/update/') || currentUrl.includes('/activity-') || currentUrl.includes('/posts/');
        
        if (isPostPage && currentUrl.includes(postUrl.split('/').pop())) {
            // We're on the post page, extract content
            console.log('[PostFetch] On post page, extracting content...');
        } else {
            // Try to find post link and navigate
            const postLink = document.querySelector(`a[href*="${postUrl.split('/').pop()}"], a[href="${postUrl}"]`);
            if (postLink) {
                console.log('[PostFetch] Found post link, attempting to extract from current view...');
                // Try to get content from the link's parent container
                const postContainer = postLink.closest('.feed-shared-update-v2, .profile-creator-shared-feed-update__container');
                if (postContainer) {
                    const textElement = postContainer.querySelector('.feed-shared-text, .update-components-text');
                    if (textElement) {
                        postContent.text = textElement.innerText?.trim() || '';
                    }
                }
            }
        }
        
        // Try multiple selectors for post content
        const contentSelectors = [
            '.feed-shared-text',
            '.update-components-text',
            '.feed-shared-update-v2__description',
            '[data-test-id="main-feed-activity-card__commentary"]',
            '.feed-shared-text-view'
        ];
        
        for (const selector of contentSelectors) {
            const element = document.querySelector(selector);
            if (element && element.innerText?.trim()) {
                postContent.text = element.innerText.trim();
                if (postContent.text.length > 50) break; // Got substantial content
            }
        }
        
        // Get author info
        const authorElement = document.querySelector('.feed-shared-actor__name, .update-components-actor__name, .feed-shared-actor__title');
        if (authorElement) {
            postContent.author = authorElement.innerText?.trim() || '';
        }
        
        // Get timestamp
        const timeElement = document.querySelector('time');
        if (timeElement) {
            postContent.timestamp = timeElement.getAttribute('datetime') || timeElement.innerText?.trim() || '';
        }
        
        // Get engagement metrics (simplified)
        const engagementElements = document.querySelectorAll('.social-actions-button, .feed-shared-social-action-bar');
        if (engagementElements.length > 0) {
            engagementElements.forEach(el => {
                const text = el.innerText || '';
                if (text.match(/\d+/)) {
                    const num = parseInt(text.match(/\d+/)[0]);
                    if (text.toLowerCase().includes('like') || text.toLowerCase().includes('reaction')) {
                        postContent.engagement.likes = num;
                    } else if (text.toLowerCase().includes('comment')) {
                        postContent.engagement.comments = num;
                    } else if (text.toLowerCase().includes('share')) {
                        postContent.engagement.shares = num;
                    }
                }
            });
        }
        
        if (postContent.text) {
            console.log('[PostFetch] ✓ Extracted post content:', postContent.text.substring(0, 100));
        } else {
            console.log('[PostFetch] ⚠ Could not extract post content, will use text from activity feed');
        }
        
        return postContent;
    } catch (e) {
        console.error('[PostFetch] ✗ Error:', e);
        // Return empty content rather than throwing, so we can fall back to activity feed text
        return {
            text: '',
            author: '',
            timestamp: '',
            engagement: { likes: 0, comments: 0, shares: 0 }
        };
    }
}

/**
 * Load and extract all posts from the recent activity page
 */
async function loadRecentActivityPage() {
    console.log('[RecentActivity] Starting to extract posts from recent activity page...');
    
    const activity = {
        posts: [],
        likes: [],
        comments: []
    };

    // Wait a bit for page to fully load
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Try multiple selectors for post containers
    const postSelectors = [
        '.feed-shared-update-v2',
        '.profile-creator-shared-feed-update__container',
        '.feed-shared-update-v2__description-wrapper',
        '[data-test-id="main-feed-activity-card"]',
        '.update-components-text'
    ];

    let postElements = [];
    for (const selector of postSelectors) {
        postElements = document.querySelectorAll(selector);
        if (postElements.length > 0) {
            console.log(`[RecentActivity] Found ${postElements.length} posts using selector: ${selector}`);
            break;
        }
    }

    if (postElements.length === 0) {
        console.log('[RecentActivity] ⚠ No posts found, trying alternative approach...');
        // Try to find any text containers that might be posts
        postElements = document.querySelectorAll('article, .feed-shared-update-v2, [data-test-id*="activity"]');
    }

    console.log(`[RecentActivity] Processing ${postElements.length} potential posts...`);

    for (let index = 0; index < Math.min(postElements.length, 20); index++) {
        const item = postElements[index];
        
        try {
            // Extract post text
            const textElement = item.querySelector('.feed-shared-text, .update-components-text, .feed-shared-text-view, [data-test-id="main-feed-activity-card__commentary"]');
            let text = textElement?.innerText?.trim() || '';
            
            // Try to expand "see more" if present
            const seeMoreBtn = item.querySelector('button[aria-label*="see more"], .feed-shared-text__see-more');
            if (seeMoreBtn && text.length < 500) {
                try {
                    seeMoreBtn.click();
                    await new Promise(resolve => setTimeout(resolve, 500));
                    const expandedText = item.querySelector('.feed-shared-text, .update-components-text')?.innerText?.trim();
                    if (expandedText && expandedText.length > text.length) {
                        text = expandedText;
                    }
                } catch (e) {
                    console.log('[RecentActivity] Could not expand post', index);
                }
            }

            if (!text || text.length < 20) {
                // Try to get text from the entire item
                text = item.innerText?.trim() || '';
            }

            if (text && text.length >= 20) {
                // Extract post URL
                let postUrl = null;
                const linkElement = item.querySelector('a[href*="/feed/update/"], a[href*="/activity-"], a[href*="/posts/"]');
                if (linkElement) {
                    postUrl = linkElement.href;
                } else {
                    // Try to construct URL from data attributes
                    const updateId = item.getAttribute('data-urn') || item.getAttribute('data-activity-id');
                    if (updateId) {
                        const currentUrl = window.location.href;
                        const baseUrl = currentUrl.split('/recent-activity')[0];
                        postUrl = `${baseUrl}/recent-activity/${updateId}/`;
                    }
                }

                // Extract timestamp
                const timeElement = item.querySelector('time');
                const timestamp = timeElement?.getAttribute('datetime') || timeElement?.innerText?.trim() || null;

                // Extract engagement metrics
                const engagement = {
                    likes: 0,
                    comments: 0,
                    shares: 0
                };

                const engagementText = item.innerText || '';
                const likesMatch = engagementText.match(/(\d+)\s*(?:like|reaction)/i);
                const commentsMatch = engagementText.match(/(\d+)\s*comment/i);
                const sharesMatch = engagementText.match(/(\d+)\s*share/i);

                if (likesMatch) engagement.likes = parseInt(likesMatch[1]);
                if (commentsMatch) engagement.comments = parseInt(commentsMatch[1]);
                if (sharesMatch) engagement.shares = parseInt(sharesMatch[1]);

                const postEntry = {
                    text: text.substring(0, 3000), // Increased limit
                    fullText: text,
                    url: postUrl,
                    timestamp: timestamp,
                    engagement: engagement,
                    type: 'post',
                    preview: text.substring(0, 100) + '...'
                };

                activity.posts.push(postEntry);
                console.log(`[RecentActivity] ✓ Extracted post ${index + 1}: ${postEntry.preview}`);
            }
        } catch (err) {
            console.log(`[RecentActivity] ⚠ Error parsing post ${index}:`, err.message);
        }
    }

    console.log(`[RecentActivity] ✓ Extracted ${activity.posts.length} posts from recent activity page`);
    return activity;
}
