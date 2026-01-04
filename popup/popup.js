document.addEventListener('DOMContentLoaded', async () => {
    // === UI Elements ===
    const apiKeyInput = document.getElementById('apiKey');
    const userGoalInput = document.getElementById('userGoal');
    const icpDefinitionInput = document.getElementById('icpDefinition');
    const offerDetailsInput = document.getElementById('offerDetails');
    const proofPointsInput = document.getElementById('proofPoints');
    const riskLevelInput = document.getElementById('riskLevel');
    const offerTypeInput = document.getElementById('offerType');

    // Main Actions
    const analyzeBtn = document.getElementById('analyzeBtn');
    const regenerateBtn = document.getElementById('regenerateBtn');
    const captureProfileBtn = document.getElementById('captureProfileBtn');

    // Status
    const statusBadge = document.getElementById('statusBadge');
    const senderProfileStatus = document.getElementById('senderProfileStatus');
    const cachedProfilePreview = document.getElementById('cachedProfilePreview');

    // Container Views
    const tabBtns = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view');
    const emptyState = document.getElementById('emptyState');
    const resultsContent = document.getElementById('resultsContent');

    // Result Elements (Scores)
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreValue = document.getElementById('scoreValue');
    const influenceCircle = document.getElementById('influenceCircle');
    const influenceValue = document.getElementById('influenceValue');
    const roleMappingBadge = document.getElementById('roleMappingBadge');

    // Result Elements (Context)
    const contextSection = document.getElementById('sharedContextSection');
    const contextScore = document.getElementById('contextScore');
    const contextBadges = document.getElementById('contextBadges');

    // Result Elements (Details)
    const fitReasonsList = document.getElementById('fitReasonsList');
    const missingInfoList = document.getElementById('missingInfoList');
    const decisionReasoningList = document.getElementById('decisionReasoningList');
    const alternateTargetsList = document.getElementById('alternateTargetsList');
    const triggerSignalsList = document.getElementById('triggerSignalsList');
    const mismatchesList = document.getElementById('mismatchesList');
    const multiThreadTargetsList = document.getElementById('multiThreadTargetsList');
    
    // Result Elements (Strategy & Transparency)
    const outreachStrategySection = document.getElementById('outreachStrategySection');
    const strategyApproach = document.getElementById('strategyApproach');
    const strategyRationale = document.getElementById('strategyRationale');
    const strategyTiming = document.getElementById('strategyTiming');
    const confidenceBadge = document.getElementById('confidenceBadge');
    const signalsUsedList = document.getElementById('signalsUsedList');
    const doSayList = document.getElementById('doSayList');
    const dontSayList = document.getElementById('dontSayList');
    
    // Related Profiles
    const relatedProfilesContainer = document.getElementById('relatedProfilesContainer');

    // Draft Tabs
    const draftTabs = document.querySelectorAll('.draft-tab');

    const debugLog = document.getElementById('debugLog');

    // === Helpers ===
    function log(msg) {
        console.log(msg);
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const ts = new Date().toISOString().split('T')[1].slice(0, 8);
        entry.innerHTML = `<span class="log-ts">[${ts}]</span> ${msg}`;
        debugLog.appendChild(entry);
        debugLog.scrollTop = debugLog.scrollHeight;
    }

    function updateStatus(msg) {
        statusBadge.textContent = msg;
        log(`Status status: ${msg}`);
    }

    log("Extension loaded. Initializing...");

    // === Check for cached analysis on load ===
    async function checkAndShowRegenerateButton() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url.includes('linkedin.com/')) {
                const cached = await checkCachedAnalysis(tab.url);
                if (cached) {
                    regenerateBtn.classList.remove('hidden');
                    log("[Cache] Showing regenerate button - cached analysis available");
                } else {
                    regenerateBtn.classList.add('hidden');
                }
            }
        } catch (e) {
            // Ignore errors
        }
    }
    
    // Check on load
    checkAndShowRegenerateButton();

    // === Load Settings ===
    const stored = await chrome.storage.local.get([
        'openai_api_key', 'user_goal', 'icp_definition',
        'offer_details', 'proof_points', 'risk_level', 'offer_type',
        'sender_profile_cache', 'sender_profile_structured', 'sender_profile_date'
    ]);

    if (stored.openai_api_key) apiKeyInput.value = stored.openai_api_key;
    if (stored.user_goal) userGoalInput.value = stored.user_goal;
    if (stored.icp_definition) icpDefinitionInput.value = stored.icp_definition;
    if (stored.offer_details) offerDetailsInput.value = stored.offer_details;
    if (stored.proof_points) proofPointsInput.value = stored.proof_points;
    if (stored.risk_level) riskLevelInput.value = stored.risk_level;
    if (stored.offer_type) offerTypeInput.value = stored.offer_type;

    if (stored.sender_profile_cache) {
        senderProfileStatus.textContent = `Cached: ${stored.sender_profile_date || 'Unknown'}`;
        senderProfileStatus.style.color = '#10b981'; // success info

        // Show structured preview if available, otherwise show text preview
        if (stored.sender_profile_structured) {
            const s = stored.sender_profile_structured;
            let preview = `${s.name}`;
            if (s.headline) preview += `\n${s.headline}`;
            if (s.currentPosition) {
                preview += `\n\nCurrent: ${s.currentPosition.title} at ${s.currentPosition.company}`;
            }
            if (s.education.length > 0) {
                preview += `\n\nEducation: ${s.education[0].school}`;
                if (s.education.length > 1) preview += ` (+${s.education.length - 1} more)`;
            }
            cachedProfilePreview.textContent = preview;
        } else {
            // Fallback to text preview for old cached data
            cachedProfilePreview.textContent = stored.sender_profile_cache.substring(0, 500) + '...';
        }
    }

    log("Settings loaded.");

    // === Auto-Save ===
    const saveSetting = (key, val) => chrome.storage.local.set({ [key]: val });

    apiKeyInput.addEventListener('change', () => saveSetting('openai_api_key', apiKeyInput.value));
    userGoalInput.addEventListener('change', () => saveSetting('user_goal', userGoalInput.value));
    icpDefinitionInput.addEventListener('change', () => saveSetting('icp_definition', icpDefinitionInput.value));
    offerDetailsInput.addEventListener('change', () => saveSetting('offer_details', offerDetailsInput.value));
    proofPointsInput.addEventListener('change', () => saveSetting('proof_points', proofPointsInput.value));
    riskLevelInput.addEventListener('change', () => saveSetting('risk_level', riskLevelInput.value));
    offerTypeInput.addEventListener('change', () => saveSetting('offer_type', offerTypeInput.value));

    // === Navigation Logic ===
    function showTab(targetId) {
        // Update Nav Buttons
        tabBtns.forEach(btn => {
            if (btn.dataset.target === targetId) btn.classList.add('active');
            else btn.classList.remove('active');
        });

        // Update Views
        views.forEach(view => {
            if (view.id === targetId) view.classList.remove('hidden');
            else classListAdd(view, 'hidden'); // safe add
        });
    }

    // Safe helper to avoid null errors on classList
    function classListAdd(el, cls) {
        if (el && el.classList) el.classList.add(cls);
    }
    function classListRemove(el, cls) {
        if (el && el.classList) el.classList.remove(cls);
    }

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            showTab(btn.dataset.target);
        });
    });

    // Draft Tabs Logic
    draftTabs.forEach(btn => {
        btn.addEventListener('click', () => {
            draftTabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Toggle Content
            document.querySelectorAll('.draft-content').forEach(c => classListAdd(c, 'hidden'));
            const target = document.getElementById(btn.dataset.draft);
            if (target) classListRemove(target, 'hidden');
        });
    });

    // === Profile Capture ===
    async function ensureContentScript(tabId) {
        try {
            await chrome.tabs.sendMessage(tabId, { action: 'PING' });
            return true;
        } catch (e) {
            log("Content script missing. Injecting...");
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: tabId },
                    files: ['scripts/content.js']
                });
                await new Promise(r => setTimeout(r, 100)); // wait for init
                return true;
            } catch (err) {
                log(`Injection failed: ${err.message}`);
                return false;
            }
        }
    }

    captureProfileBtn.addEventListener('click', async () => {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url.includes('linkedin.com/in/')) {
                alert('Navigate to your own LinkedIn profile first!');
                return;
            }

            updateStatus("Capturing...");
            if (!(await ensureContentScript(tab.id))) throw new Error("Connection failed.");

            const response = await chrome.tabs.sendMessage(tab.id, { action: 'SCRAPE_PROFILE' });
            log(`Response: success=${response?.success}, hasData=${!!response?.data}, hasStructured=${!!response?.structured}`);
            if (!response?.success) throw new Error("Scrape failed.");

            const now = new Date().toLocaleDateString();
            const data = response.data;

            // Use GPT to extract structured data
            updateStatus("Analyzing with GPT...");
            log("Calling GPT to extract structured data...");
            const structured = await extractProfileWithGPT(data, apiKeyInput.value);
            log('GPT extraction complete. Name: \"${structured.name}\"');

            log(`Structured name: "${structured?.name || 'EMPTY'}"`);
            log(`Structured headline: "${structured?.headline || 'EMPTY'}"`);
            log(`Exp count: ${structured?.experience?.length || 0}, Edu count: ${structured?.education?.length || 0} `);

            await chrome.storage.local.set({
                sender_profile_cache: data.substring(0, 20000),
                sender_profile_structured: structured,
                sender_profile_date: now
            });

            log("Data saved to chrome.storage.local");

            senderProfileStatus.textContent = `Cached: ${now} `;
            senderProfileStatus.style.color = '#10b981';

            // Create a better preview from structured data
            let preview = `${structured.name} `;
            if (structured.headline) preview += `\n${structured.headline} `;
            if (structured.currentPosition) {
                preview += `\n\nCurrent: ${structured.currentPosition.title} at ${structured.currentPosition.company} `;
            }
            if (structured.education.length > 0) {
                preview += `\n\nEducation: ${structured.education[0].school} `;
                if (structured.education.length > 1) preview += ` (+${structured.education.length - 1} more)`;
            }

            cachedProfilePreview.textContent = preview;
            updateStatus("Saved!");
            log("Profile captured.");

        } catch (e) {
            alert(e.message);
            updateStatus("Error");
        }
    });

    /**
     * Extract structured profile data using GPT
     */
    async function extractProfileWithGPT(profileText, apiKey) {
        if (!apiKey) throw new Error("API key required for GPT extraction");

        const prompt = `Extract structured profile information from this LinkedIn profile text.

LINKEDIN PROFILE TEXT:
${profileText.substring(0, 15000)}

Extract and return ONLY a JSON object with this exact structure:
        {
            "name": "Full Name",
                "headline": "Professional Title/Headline",
                    "location": "City, Country",
                        "about": "About/Summary text",
                            "currentPosition": {
                "title": "Job Title",
                    "company": "Company Name",
                        "duration": "Time period"
            },
            "experience": [
                {
                    "title": "Job Title",
                    "company": "Company Name",
                    "duration": "Time period",
                    "description": "Role description"
                }
            ],
                "education": [
                    {
                        "school": "School Name",
                        "degree": "Degree/Field",
                        "duration": "Years attended"
                    }
                ]
        }

        Rules:
        - Extract ALL work experience entries(not just current)
            - Extract ALL education entries
                - If information is missing, use empty string ""
                    - Return valid JSON only`;

        log("Sending GPT extraction request...");
        const gptResponse = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey} `
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a data extraction assistant. Extract LinkedIn profile data and return valid JSON only." },
                    { role: "user", content: prompt }
                ],
                temperature: 0.1,
                response_format: { type: "json_object" }
            })
        });

        if (!gptResponse.ok) {
            const err = await gptResponse.json();
            throw new Error(err.error?.message || 'GPT API Error');
        }

        const gptData = await gptResponse.json();
        const content = gptData.choices[0].message.content;

        log("Received GPT response, parsing JSON...");
        const parsed = JSON.parse(content);
        log(`Parsed profile: ${JSON.stringify(parsed).substring(0, 200)}...`);

        return parsed;
    }

    /**
     * Extract structured prospect data using GPT
     */
    async function extractProspectWithGPT(profileText, activity, apiKey) {
        if (!apiKey) throw new Error("API key required for prospect extraction");

        log("[ProspectExtract] Starting extraction...");
        log("[ProspectExtract] Profile text length:", profileText.length);
        log("[ProspectExtract] Activity items:", activity ?
            `${activity.posts.length} posts, ${activity.likes.length} likes, ${activity.comments.length} comments` : 'none');
        //log("[ProspectExtract] Related profiles:", relatedProfiles ? `${relatedProfiles.length} profiles` : 'none');

        // Format activity for the extraction prompt
        let activityText = '';
        if (activity && (activity.posts.length > 0 || activity.likes.length > 0 || activity.comments.length > 0)) {
            activityText = '\n\nRECENT ACTIVITY:\n';
            if (activity.posts.length > 0) {
                activityText += 'Posts:\n';
                activity.posts.forEach((post, i) => {
                    activityText += `${i + 1}. ${post.text.substring(0, 300)}\n`;
                });
            }
            if (activity.likes.length > 0) {
                activityText += '\nLiked:\n';
                activity.likes.forEach((like, i) => {
                    activityText += `${i + 1}. ${like.text.substring(0, 200)}\n`;
                });
            }
            if (activity.comments.length > 0) {
                activityText += '\nCommented on:\n';
                activity.comments.forEach((comment, i) => {
                    activityText += `${i + 1}. ${comment.text.substring(0, 200)}\n`;
                });
            }
        }

        const prompt = `Extract structured profile data from this LinkedIn prospect.

LINKEDIN PROFILE TEXT:
${profileText.substring(0, 30000)}
${activityText}

Extract and return ONLY a JSON object with this structure:
{
  "name": "Full Name",
  "headline": "Professional Title/Headline",
  "location": "City, Country",
  "about": "About/Summary section text",
  "currentPosition": {
    "title": "Current Job Title",
    "company": "Current Company Name",
    "duration": "Time period (e.g., 2022 - Present)"
  },
  "experience": [
    {
      "title": "Job Title",
      "company": "Company Name",
      "duration": "Time period",
      "description": "Brief role description"
    }
  ],
  "education": [
    {
      "school": "School Name",
      "degree": "Degree and Field",
      "duration": "Years (e.g., 2010 - 2014)"
    }
  ],
  "interests": {
    "topics": ["topic1", "topic2"],
    "professionalFocus": ["focus area 1", "focus area 2"],
    "recentEngagement": "Brief summary of what they're posting/engaging with based on activity"
  },
  "relatedProfiles": [
    {
      "name": "Full Name",
      "url": "LinkedIn profile URL",
      "headline": "Profile headline/title",
      "location": "Location if available"
    }
  ]
}

RULES:
- Extract ALL experience and education entries
- If info missing, use empty string ""
- For interests, analyze their recent posts/likes to identify topics
- For relatedProfiles, extract ALL profiles mentioned in the "People also viewed" or "People you may know" sections
- Include name, LinkedIn URL, headline, and location for each related profile
- If no related profiles found, return empty array []
- Return valid JSON only`;

        log("[ProspectExtract] Sending to GPT...");
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a data extraction assistant. Extract LinkedIn profile data and return valid JSON only." },
                    { role: "user", content: prompt }
                ],
                temperature: 0.1,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            log("[ProspectExtract] ✗ API Error:", err.error?.message);
            throw new Error(err.error?.message || 'GPT API Error');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        log("[ProspectExtract] ✓ Received response, parsing...");
        const parsed = JSON.parse(content);
        log("[ProspectExtract] ✓ Extracted:", parsed.name);
        log("[ProspectExtract]   Company:", parsed.currentPosition?.company || 'N/A');
        log("[ProspectExtract]   Interests:", parsed.interests?.topics?.join(', ') || 'N/A');

        return parsed;
    }

    /**
     * Fetch post content from URLs using content script
     */
    async function fetchPostsFromUrls(postUrls, tabId) {
        if (!postUrls || postUrls.length === 0) {
            log("[PostFetch] No post URLs provided");
            return [];
        }

        log(`[PostFetch] Fetching content from ${postUrls.length} post URLs...`);
        const fetchedPosts = [];

        for (let i = 0; i < Math.min(postUrls.length, 5); i++) { // Limit to 5 posts
            const url = postUrls[i];
            if (!url) continue;

            try {
                log(`[PostFetch] Fetching post ${i + 1}/${Math.min(postUrls.length, 5)}: ${url}`);
                
                // Send message to content script to fetch post content
                const response = await chrome.tabs.sendMessage(tabId, {
                    action: 'FETCH_POST_CONTENT',
                    url: url
                });

                if (response?.success && response.content) {
                    fetchedPosts.push({
                        url: url,
                        text: response.content.text,
                        author: response.content.author,
                        timestamp: response.content.timestamp,
                        engagement: response.content.engagement
                    });
                    log(`[PostFetch] ✓ Fetched post ${i + 1}: ${response.content.text.substring(0, 50)}...`);
                } else {
                    log(`[PostFetch] ⚠ Failed to fetch post ${i + 1}`);
                }
            } catch (e) {
                log(`[PostFetch] ✗ Error fetching post ${i + 1}: ${e.message}`);
            }
        }

        return fetchedPosts;
    }

    /**
     * Summarize posts and extract prospect interests using GPT
     * Now filters to only include posts with important content
     */
    async function summarizePostsAndExtractInterests(posts, postUrls, tabId, apiKey) {
        if (!apiKey) throw new Error("API key required for post summarization");
        
        let postsToAnalyze = [];
        
        // If we have post URLs, fetch full content from them
        if (postUrls && postUrls.length > 0 && tabId) {
            log("[PostSummary] Fetching full post content from URLs...");
            const fetchedPosts = await fetchPostsFromUrls(postUrls, tabId);
            postsToAnalyze = fetchedPosts;
        } else if (posts && posts.length > 0) {
            // Fallback to posts from activity feed
            postsToAnalyze = posts.map(p => ({
                url: p.url,
                text: p.text || p.fullText || '',
                timestamp: p.timestamp
            }));
        }
        
        if (postsToAnalyze.length === 0) {
            log("[PostSummary] No posts available");
            return null;
        }

        log(`[PostSummary] Analyzing ${postsToAnalyze.length} posts...`);

        // First, use GPT to identify which posts have important content
        const postsText = postsToAnalyze.map((post, index) => {
            return `Post ${index + 1}${post.url ? ` (${post.url})` : ''}:\n${post.text}\n${post.timestamp ? `Posted: ${post.timestamp}` : ''}\n`;
        }).join('\n---\n\n');

        const filterPrompt = `You are analyzing LinkedIn posts to identify which ones contain important, actionable content for sales outreach.

POSTS TO ANALYZE:
${postsText.substring(0, 20000)}

For each post, determine if it contains:
- Professional insights or thought leadership
- Pain points or challenges mentioned
- Buying signals (initiatives, projects, needs)
- Industry trends or discussions
- Personal interests that could be conversation starters
- Questions or engagement that shows active interest

Return ONLY a JSON object with this structure:
{
  "importantPosts": [
    {
      "index": 1,
      "url": "post url if available",
      "importanceScore": number (0-100),
      "reason": "Why this post is important",
      "keyContent": "The most important part of this post"
    }
  ],
  "summary": "Brief summary of what types of important content were found"
}

Rules:
- Only include posts with importanceScore >= 50
- Focus on posts with actionable insights for outreach
- Return valid JSON only`;

        log("[PostSummary] Filtering posts for important content...");
        const filterResponse = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a sales intelligence assistant. Identify important posts. Return valid JSON only." },
                    { role: "user", content: filterPrompt }
                ],
                temperature: 0.2,
                response_format: { type: "json_object" }
            })
        });

        if (!filterResponse.ok) {
            const err = await filterResponse.json();
            log("[PostSummary] ✗ Filter API Error:", err.error?.message);
            throw new Error(err.error?.message || 'Post Filtering API Error');
        }

        const filterData = await filterResponse.json();
        const filterContent = filterData.choices[0].message.content;
        const filterResult = JSON.parse(filterContent);

        log(`[PostSummary] ✓ Identified ${filterResult.importantPosts?.length || 0} important posts`);

        // Filter posts to only include important ones
        const importantPosts = postsToAnalyze.filter((post, index) => {
            return filterResult.importantPosts?.some(ip => ip.index === index + 1 && ip.importanceScore >= 50);
        });

        if (importantPosts.length === 0) {
            log("[PostSummary] No important posts found, using all posts");
            // Fallback to all posts if none are marked important
        } else {
            postsToAnalyze = importantPosts;
            log(`[PostSummary] Using ${postsToAnalyze.length} important posts for detailed analysis`);
        }

        // Now summarize the important posts
        const importantPostsText = postsToAnalyze.map((post, index) => {
            const filterInfo = filterResult.importantPosts?.find(ip => 
                postsToAnalyze.indexOf(post) === ip.index - 1 || 
                (post.url && ip.url && post.url.includes(ip.url.split('/').pop()))
            );
            return `Post ${index + 1}${post.url ? ` (${post.url})` : ''}:\n${post.text}\n${filterInfo ? `Importance: ${filterInfo.reason}` : ''}\n`;
        }).join('\n---\n\n');

        const prompt = `You are analyzing a prospect's LinkedIn posts to understand their interests, professional focus, and potential buying signals.

IMPORTANT POSTS (filtered for actionable content):
${importantPostsText.substring(0, 15000)}

Analyze these posts and provide:
1. **Key Topics**: What subjects/themes do they post about most?
2. **Professional Focus**: What are their main professional interests and concerns?
3. **Pain Points**: What challenges or problems do they mention or hint at?
4. **Buying Signals**: Any indicators of initiatives, projects, or needs that suggest they might be looking for solutions?
5. **Engagement Patterns**: What types of content do they create (thought leadership, questions, updates, etc.)?
6. **Industry Trends**: What industry trends or topics are they discussing?
7. **Personal Interests**: Any personal interests that could be conversation starters?

Return ONLY a JSON object with this structure:
{
  "summary": "Overall summary of their posting activity and themes",
  "keyTopics": ["topic1", "topic2", "topic3"],
  "professionalFocus": ["focus1", "focus2"],
  "painPoints": ["pain point 1", "pain point 2"],
  "buyingSignals": ["signal1", "signal2"],
  "engagementPatterns": ["pattern1", "pattern2"],
  "industryTrends": ["trend1", "trend2"],
  "personalInterests": ["interest1", "interest2"],
  "topPosts": [
    {
      "index": 1,
      "summary": "Brief summary of this post",
      "keyInsight": "Main insight or hook from this post",
      "relevanceToOutreach": "Why this post is relevant for outreach"
    }
  ],
  "outreachHooks": ["hook1 based on posts", "hook2 based on posts"],
  "conversationStarters": ["starter1", "starter2"]
}

Rules:
- Be specific and actionable
- Focus on insights that can be used in personalized outreach
- Identify concrete buying signals when present
- Return valid JSON only`;

        log("[PostSummary] Sending summarization request to GPT...");
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a sales intelligence assistant. Analyze posts and extract actionable insights. Return valid JSON only." },
                    { role: "user", content: prompt }
                ],
                temperature: 0.3,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            log("[PostSummary] ✗ API Error:", err.error?.message);
            throw new Error(err.error?.message || 'Post Summarization API Error');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        log("[PostSummary] ✓ Received response, parsing...");
        const parsed = JSON.parse(content);
        log(`[PostSummary] ✓ Extracted ${parsed.keyTopics?.length || 0} topics, ${parsed.buyingSignals?.length || 0} buying signals`);
        
        return parsed;
    }

    /**
     * Analyze related profiles to find relevant prospects
     */
    async function analyzeRelatedProfiles(profiles, sellerGoal, icpDefinition, sellerOffer, apiKey) {
        if (!apiKey) throw new Error("API key required for profile analysis");
        if (!profiles || profiles.length === 0) {
            log("[RelatedProfiles] No profiles to analyze");
            return [];
        }

        log(`[RelatedProfiles] Analyzing ${profiles.length} profiles for relevance...`);

        const profilesText = profiles.map((profile, index) => {
            return `Profile ${index + 1}:
Name: ${profile.name}
Headline: ${profile.headline}
Location: ${profile.location || 'Not specified'}
LinkedIn: ${profile.url}`;
        }).join('\n\n---\n\n');

        const prompt = `You are analyzing LinkedIn profiles to identify which ones are relevant prospects for a seller.

SELLER CONTEXT:
- Goal: ${sellerGoal || 'Not specified'}
- ICP Definition: ${icpDefinition || 'Not specified'}
- Offer: ${sellerOffer || 'Not specified'}

RELATED PROFILES:
${profilesText}

For each profile, determine:
1. **Relevance Score (0-100)**: How well does this profile match the ICP?
2. **Fit Reasons**: Why this profile might be a good fit (industry, role, company, etc.)
3. **Potential Value**: Why this person might need the seller's offer
4. **Decision Power**: Likely buyer / influencer / not relevant

Return ONLY a JSON object with this structure:
{
  "relevantProfiles": [
    {
      "name": "Full Name",
      "url": "LinkedIn profile URL",
      "headline": "Profile headline",
      "relevanceScore": number (0-100),
      "fitReasons": ["reason1", "reason2"],
      "potentialValue": "Why they might need the offer",
      "decisionPower": "Buyer | Influencer | Not Relevant"
    }
  ]
}

Rules:
- Only include profiles with relevanceScore >= 50
- Sort by relevanceScore (highest first)
- Limit to top 5 most relevant profiles
- Be specific about why each profile is relevant
- Return valid JSON only`;

        log("[RelatedProfiles] Sending analysis request to GPT...");
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a sales intelligence assistant. Analyze profiles and return valid JSON only." },
                    { role: "user", content: prompt }
                ],
                temperature: 0.3,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            log("[RelatedProfiles] ✗ API Error:", err.error?.message);
            throw new Error(err.error?.message || 'Related Profiles Analysis API Error');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        log("[RelatedProfiles] ✓ Received response, parsing...");
        const parsed = JSON.parse(content);
        const relevant = parsed.relevantProfiles || [];
        log(`[RelatedProfiles] ✓ Found ${relevant.length} relevant profiles`);
        
        return relevant;
    }

    /**
     * Render related profiles in the UI
     */
    function renderRelatedProfiles(profiles) {
        if (!profiles || profiles.length === 0) {
            relatedProfilesContainer.innerHTML = '<p class="empty-state">No relevant related profiles found.</p>';
            return;
        }

        relatedProfilesContainer.innerHTML = '';
        
        profiles.forEach((profile, index) => {
            const profileCard = document.createElement('div');
            profileCard.className = 'related-profile-card';
            
            const scoreColor = profile.relevanceScore >= 70 ? '#4caf50' : profile.relevanceScore >= 50 ? '#ffc107' : '#f44336';
            
            profileCard.innerHTML = `
                <div class="profile-header">
                    <div class="profile-info">
                        <a href="${profile.url}" target="_blank" class="profile-link" data-url="${profile.url}">
                            <strong>${profile.name}</strong>
                        </a>
                        <div class="profile-headline">${profile.headline}</div>
                    </div>
                    <div class="relevance-score" style="color: ${scoreColor}">
                        ${profile.relevanceScore}
                    </div>
                </div>
                <div class="profile-details">
                    <div class="fit-reasons">
                        <strong>Fit:</strong> ${profile.fitReasons?.join(', ') || 'N/A'}
                    </div>
                    <div class="potential-value">
                        <strong>Value:</strong> ${profile.potentialValue || 'N/A'}
                    </div>
                    <div class="decision-power">
                        <strong>Role:</strong> ${profile.decisionPower || 'N/A'}
                    </div>
                </div>
            `;
            
            relatedProfilesContainer.appendChild(profileCard);
        });

        // Add click handlers to open profiles in new tabs
        relatedProfilesContainer.querySelectorAll('.profile-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const url = link.getAttribute('data-url');
                if (url) {
                    chrome.tabs.create({ url: url });
                }
            });
        });
    }

    /**
     * Research companies from prospect's experience in context of seller's offer
     */
    async function researchCompanies(structuredProspect, sellerOffer, sellerGoal, icpDefinition, apiKey) {
        if (!apiKey) throw new Error("API key required for company research");
        if (!structuredProspect || !structuredProspect.experience || structuredProspect.experience.length === 0) {
            log("[CompanyResearch] No experience data available");
            return null;
        }

        log("[CompanyResearch] Starting company research...");
        
        // Extract unique companies from experience
        const companies = [];
        const seenCompanies = new Set();
        
        // Add current company
        if (structuredProspect.currentPosition?.company) {
            companies.push({
                name: structuredProspect.currentPosition.company,
                role: structuredProspect.currentPosition.title,
                duration: structuredProspect.currentPosition.duration,
                isCurrent: true
            });
            seenCompanies.add(structuredProspect.currentPosition.company.toLowerCase());
        }
        
        // Add past companies
        structuredProspect.experience.forEach(exp => {
            const companyName = exp.company?.trim();
            if (companyName && !seenCompanies.has(companyName.toLowerCase())) {
                companies.push({
                    name: companyName,
                    role: exp.title || 'Unknown',
                    duration: exp.duration || 'Unknown',
                    description: exp.description || '',
                    isCurrent: false
                });
                seenCompanies.add(companyName.toLowerCase());
            }
        });

        if (companies.length === 0) {
            log("[CompanyResearch] No companies found in prospect experience");
            return null;
        }

        log(`[CompanyResearch] Researching ${companies.length} companies: ${companies.map(c => c.name).join(', ')}`);

        const prompt = `You are a sales research assistant. Analyze companies from a prospect's work history in the context of what a seller is trying to sell.

SELLER CONTEXT:
- Goal: ${sellerGoal || 'Not specified'}
- Offer: ${sellerOffer || 'Not specified'}
- ICP Definition: ${icpDefinition || 'Not specified'}

PROSPECT'S COMPANIES:
${JSON.stringify(companies, null, 2)}

For each company, provide concise research on:
1. **Company Fit**: How well does this company match the ICP? (Industry, size, geography, etc.)
2. **Relevance to Offer**: Why might this company need or benefit from the seller's offer?
3. **Prospect's Role Context**: How does the prospect's role at this company relate to the seller's offer?
4. **Buying Signals**: Any indicators that this company might be a good fit (based on industry trends, company type, role responsibilities)
5. **Potential Challenges**: Why this company might NOT be a fit

Focus on the CURRENT company first, then past companies if relevant.

Return ONLY a JSON object with this structure:
{
  "currentCompany": {
    "companyName": "Company Name",
    "fitScore": number (0-100),
    "relevanceToOffer": "Why this company might need the offer",
    "roleContext": "How prospect's role relates to offer",
    "buyingSignals": ["signal1", "signal2"],
    "challenges": ["challenge1", "challenge2"],
    "researchSummary": "Concise summary of company fit and relevance"
  },
  "pastCompanies": [
    {
      "companyName": "Company Name",
      "fitScore": number (0-100),
      "relevanceToOffer": "Brief relevance",
      "roleContext": "How role relates",
      "researchSummary": "Brief summary"
    }
  ],
  "overallCompanyInsights": "Overall insights about prospect's company background in relation to seller's offer",
  "bestCompanyFit": "Which company (current or past) shows the strongest fit and why"
}

Rules:
- Be concise but specific
- Focus on actionable insights
- If information is unclear, note it but still provide analysis
- Return valid JSON only`;

        log("[CompanyResearch] Sending research request to GPT...");
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a sales research assistant. Analyze companies and return valid JSON only." },
                    { role: "user", content: prompt }
                ],
                temperature: 0.3,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            log("[CompanyResearch] ✗ API Error:", err.error?.message);
            throw new Error(err.error?.message || 'Company Research API Error');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        log("[CompanyResearch] ✓ Received response, parsing...");
        const parsed = JSON.parse(content);
        log(`[CompanyResearch] ✓ Research complete for ${parsed.currentCompany?.companyName || 'companies'}`);
        
        return parsed;
    }

    // === Helper Functions for Analysis ===
    function setScore(circle, label, value) {
        const val = value || 0;
        label.textContent = val;
        circle.className = 'score-circle'; // reset
        if (val >= 80) circle.classList.add('score-high');
        else if (val >= 50) circle.classList.add('score-med');
        else circle.classList.add('score-low');
    }

    function renderList(element, items) {
        element.innerHTML = '';
        if (!items || items.length === 0) {
            const li = document.createElement('li');
            li.textContent = "None identified.";
            element.appendChild(li);
            return;
        }
        items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            element.appendChild(li);
        });
    }

    function renderResults(data, riskStrategy) {
        emptyState.classList.add('hidden');
        resultsContent.classList.remove('hidden');

        // Scores
        setScore(scoreCircle, scoreValue, data.fitScore);
        setScore(influenceCircle, influenceValue, data.influenceScore);

        // Role Mapping
        const mapping = data.roleMapping || "Unknown";
        roleMappingBadge.textContent = mapping;
        roleMappingBadge.className = 'role-badge';
        if (mapping.includes('Buyer')) roleMappingBadge.classList.add('role-buyer');
        else if (mapping.includes('Influencer')) roleMappingBadge.classList.add('role-influencer');
        else roleMappingBadge.classList.add('role-avoid');

        // Shared Context Banner
        if (data.sharedContextScore > 20) {
            contextSection.classList.remove('hidden');
            contextScore.textContent = `${data.sharedContextScore} % Match`;
            contextBadges.innerHTML = '';

            (data.sharedSignals || []).forEach(signal => {
                const badge = document.createElement('span');
                badge.className = 'context-badge';
                badge.textContent = signal; // e.g., "🎓 Same College"
                contextBadges.appendChild(badge);
            });
        } else {
            contextSection.classList.add('hidden');
        }

        // Lists
        renderList(fitReasonsList, data.fitReasons);
        renderList(missingInfoList, data.missingInfo);
        renderList(decisionReasoningList, data.decisionReasoning);
        renderList(alternateTargetsList, data.alternateTargets);
        renderList(triggerSignalsList, data.triggerSignals);
        renderList(mismatchesList, data.mismatches);
        renderList(multiThreadTargetsList, data.multiThreadTargets);

        // Outreach Strategy
        if (data.outreachStrategy) {
            outreachStrategySection.classList.remove('hidden');
            strategyApproach.textContent = data.outreachStrategy.recommendedApproach || 'Not specified';
            strategyRationale.textContent = data.outreachStrategy.rationale || '';
            strategyTiming.textContent = data.outreachStrategy.timing ? `⏰ ${data.outreachStrategy.timing}` : '';
        } else {
            outreachStrategySection.classList.add('hidden');
        }

        // Transparency Layer
        if (data.confidence) {
            confidenceBadge.textContent = data.confidence;
            confidenceBadge.className = 'confidence-' + data.confidence.toLowerCase();
        }
        renderList(signalsUsedList, data.signalsUsed);
        renderList(doSayList, data.doSay);
        renderList(dontSayList, data.dontSay);

        // Drafts with Strategy Label
        let strategyLabel = `Strategy: ${riskStrategy} | ${data.draftStrategy || 'Standard'}`;
        // If context was used
        if (data.sharedContextScore > 50 && riskStrategy !== 'Safe') {
            strategyLabel += ` | 🤝 Warm Intro Used`;
        }
        if (data.outreachStrategy?.recommendedApproach) {
            strategyLabel += ` | ${data.outreachStrategy.recommendedApproach}`;
        }

        document.getElementById('connRequest').innerHTML = `<strong>${strategyLabel}</strong><br/><br/>${data.connectionRequest || "No draft."}`;
        document.getElementById('coldEmail').innerHTML = `<strong>${strategyLabel}</strong><br/><br/>${data.coldEmail || "No draft."}`;

        // Message Variants
        if (data.messageVariants) {
            let variantsHtml = `<strong>Message Variants</strong><br/><br/>`;
            if (data.messageVariants.shortPunchy) {
                variantsHtml += `<div class="variant-section"><strong>Short Punchy:</strong><br/>${data.messageVariants.shortPunchy}</div><br/>`;
            }
            if (data.messageVariants.credibilityFirst) {
                variantsHtml += `<div class="variant-section"><strong>Credibility-First:</strong><br/>${data.messageVariants.credibilityFirst}</div><br/>`;
            }
            if (data.messageVariants.insightLed) {
                variantsHtml += `<div class="variant-section"><strong>Insight-Led / Value-First:</strong><br/>${data.messageVariants.insightLed}</div><br/>`;
            }
            if (data.messageVariants.softAsk) {
                variantsHtml += `<div class="variant-section"><strong>Soft-Ask / Low-Friction:</strong><br/>${data.messageVariants.softAsk}</div>`;
            }
            document.getElementById('messageVariants').innerHTML = variantsHtml;
        } else {
            document.getElementById('messageVariants').innerHTML = 'No variants generated.';
        }

        // Message Sequence
        if (data.messageSequence) {
            let sequenceHtml = `<strong>Complete Outreach Sequence</strong><br/><br/>`;
            if (data.messageSequence.firstMessage) {
                sequenceHtml += `<div class="sequence-item"><strong>First Message:</strong><br/>${data.messageSequence.firstMessage}</div><br/>`;
            }
            if (data.messageSequence.followUp1) {
                sequenceHtml += `<div class="sequence-item"><strong>Follow-up 1 (2-3 days):</strong><br/>${data.messageSequence.followUp1}</div><br/>`;
            }
            if (data.messageSequence.followUp2) {
                sequenceHtml += `<div class="sequence-item"><strong>Follow-up 2 (1 week):</strong><br/>${data.messageSequence.followUp2}</div><br/>`;
            }
            if (data.messageSequence.followUp3) {
                sequenceHtml += `<div class="sequence-item"><strong>Follow-up 3 (2 weeks):</strong><br/>${data.messageSequence.followUp3}</div><br/>`;
            }
            if (data.messageSequence.breakupMessage) {
                sequenceHtml += `<div class="sequence-item"><strong>Breakup Message:</strong><br/>${data.messageSequence.breakupMessage}</div>`;
            }
            document.getElementById('messageSequence').innerHTML = sequenceHtml;
        } else {
            document.getElementById('messageSequence').innerHTML = 'No sequence generated.';
        }
    }

    async function callOpenAI(inputs, prospectData, senderData, activity, company, structuredProspect, companyResearch, postSummary) {
        log("[CallOpenAI] Sender data length: " + (senderData ? senderData.length : 0));
        log("[CallOpenAI] Prospect data length: " + prospectData.length);
        log("[CallOpenAI] Structured prospect: " + (structuredProspect ? structuredProspect.name : 'none'));
        log("[CallOpenAI] Sender preview: " + (senderData ? senderData.substring(0, 300) : "N/A"));
        log("[CallOpenAI] Prospect preview: " + prospectData.substring(0, 300));

        log("[CallOpenAI] Activity: " + (activity ? `${activity.posts.length} posts, ${activity.likes.length} likes` : 'none'));
        log("[CallOpenAI] Company: " + (company?.name || 'none'));
        log("[CallOpenAI] Company Research: " + (companyResearch ? `Available for ${companyResearch.currentCompany?.companyName || 'companies'}` : 'Not available'));
        log("[CallOpenAI] Post Summary: " + (postSummary ? `Available - ${postSummary.keyTopics?.length || 0} topics, ${postSummary.buyingSignals?.length || 0} signals` : 'Not available'));

        // Format activity for GPT prompt
        let activityText = '';
        if (activity && (activity.posts.length > 0 || activity.likes.length > 0 || activity.comments.length > 0)) {
            activityText = '\n\n## PROSPECT RECENT ACTIVITY\n';
            if (activity.posts.length > 0) {
                activityText += '\n### Recent Posts:\n';
                activity.posts.forEach((post, i) => {
                    activityText += `${i + 1}. ${post.text}\n`;
                });
            }
            if (activity.likes.length > 0) {
                activityText += '\n### Recently Liked:\n';
                activity.likes.forEach((like, i) => {
                    activityText += `${i + 1}. ${like.text}\n`;
                });
            }
            if (activity.comments.length > 0) {
                activityText += '\n### Recent Comments:\n';
                activity.comments.forEach((comment, i) => {
                    activityText += `${i + 1}. ${comment.text}\n`;
                });
            }
        }

        const prompt = `
You are an elite Sales Copilot.

# INPUTS

## 1. YOU Layer(The Seller)
    - Goal: ${inputs.goal}
    - Offer: ${inputs.offer}
    - Proof Points: ${inputs.proof}
    - ICP: ${inputs.icp}

    [SENDER PROFILE RAW DATA]
        ${senderData ? senderData.substring(0, 15000) : "No sender profile provided."}

## 2. PLAY Layer(The Strategy)
    - Risk Level: ${inputs.risk}
    - Offer Type: ${inputs.offerType}

## 3. THEM Layer(Prospect Data)
    [PROSPECT PROFILE RAW DATA]
        ${prospectData.substring(0, 40000)}
${activityText}

    [STRUCTURED PROSPECT DATA]
        ${structuredProspect ? JSON.stringify(structuredProspect, null, 2) : 'Not available'}
    
    [COMPANY INFO]
        ${company ? `Company: ${company.name}\nLinkedIn URL: ${company.linkedinUrl || 'N/A'}` : 'Not available'}

    [COMPANY RESEARCH]
        ${companyResearch ? JSON.stringify(companyResearch, null, 2) : 'Not available'}
        This research analyzes companies from the prospect's work history in context of the seller's offer.
        Use this to:
        - Understand company fit and relevance
        - Identify buying signals from company background
        - Contextualize the prospect's role in relation to the offer
        - Reference specific company insights in messaging

    [POST SUMMARY & INTERESTS]
        ${postSummary ? JSON.stringify(postSummary, null, 2) : 'Not available'}
        This is a detailed analysis of the prospect's LinkedIn posts, summarizing their content and extracting:
        - Key topics and professional focus areas
        - Pain points and challenges mentioned
        - Buying signals from their posts
        - Engagement patterns and content types
        - Industry trends they discuss
        - Personal interests
        - Specific outreach hooks and conversation starters from their posts
        Use this to:
        - Reference specific posts or topics in messaging
        - Use their own words and interests as hooks
        - Identify buying signals from their content
        - Create personalized conversation starters
        - Align messaging with their professional focus

# INSTRUCTIONS

## A.MATCHING ENGINE(Sender vs Prospect)
Compare the SENDER and PROSPECT profiles to find specific overlaps:
        1. ** Identity **: Same College / University, Ex - Company(Alumni), Same Current Industry ?
        2. ** Location **: Same City / Region ?
        3. ** Shared Context Score(0 - 100) **: Rate the strengthen of the personal connection.
   - 80 +: Same Company same time OR Close friend connection visible.
   - 60 +: Same School OR Same Ex - Company.
   - 40 +: Same City + Industry.
   - < 20: No overlap.

## B.SCORING & MAPPING
    - ** Fit Score(0 - 100) **: Match vs ICP. Consider:
        - Industry match
        - Company size (if available from company info or company research)
        - Geography (if available)
        - Role/function alignment
        - Trigger signals from posts/activity
        - **Company Research Insights**: Use the company research to understand fit based on prospect's current and past companies
        - Weight the current company research more heavily than past companies
    - ** Influence Score(0 - 100) **: Decision Power Score. Assess:
        - Seniority level (from structured data: currentPosition.title, experience)
        - Company size and role scope
        - Authority indicators in headline/about
    - ** Role Mapping **: Classify as: Buyer / Strong Influencer / Champion / Not Ideal
    - ** Trigger Signals **: Identify initiative hints from posts/role language that suggest buying intent


## C. INTEREST MAPPING
Use the structured prospect data AND the detailed post summary to analyze:
- **Topics of Interest**: What subjects do they post about or engage with? (Use postSummary.keyTopics)
- **Professional Focus**: Career themes visible in their content (Use postSummary.professionalFocus)
- **Pain Points**: What challenges do they mention? (Use postSummary.painPoints)
- **Outreach Hooks**: Specific posts or topics that could be referenced (Use postSummary.outreachHooks and postSummary.topPosts)
- **Trigger Signals**: Look for initiative hints from posts/role language that indicate buying intent (Use postSummary.buyingSignals)
- **Conversation Starters**: Use postSummary.conversationStarters for natural openings

## D.MESSAGING ENGINE
Generate "Connection Request" & "Cold Email" using ** ${inputs.risk} ** strategy.

- ** IF Shared Context > 50 AND Risk != 'Safe' **:
        - USE THE SHARED SIGNAL as the hook(e.g. "Saw we both worked at Oracle...").
- ** ELSE IF Post Summary has strong hooks **:
        - Reference specific posts or topics from postSummary (e.g., "Saw your post about [topic] - really resonated with...").
        - Use conversation starters from postSummary.conversationStarters.
        - Reference their pain points or buying signals from posts.
- ** ELSE IF Company Research shows strong fit **:
        - Reference company-specific insights from the research (e.g., "Noticed you're at [Company] - companies in your industry often face [relevant challenge]").
        - Use buying signals identified in company research.
- ** ELSE **:
        - Use standard hooks: Role, Industry, Post, or trigger signals from their activity/interests.

**PRIORITY**: When post summary is available, prioritize using:
- Specific post references (postSummary.topPosts)
- Their own words and topics (postSummary.keyTopics)
- Buying signals from posts (postSummary.buyingSignals)
- Conversation starters (postSummary.conversationStarters)

**IMPORTANT**: When company research is available, incorporate specific insights about:
- Why their current/past companies might need the offer
- How their role relates to the seller's solution
- Company-specific buying signals or challenges

## E. OUTREACH STRATEGY ENGINE
Based on the analysis, recommend the best outreach approach:
- **Direct Pitch**: Only when strong fit (Fit Score > 70) and clear decision-maker
- **Warm-up**: Comment/like + DM sequence when shared context exists or trigger signals present
- **Referral Route**: Suggest "who owns X?" approach when influencer but not buyer
- **Multi-threading**: Recommend 2-4 roles to engage in the same company
- **Partner-led**: When relevant partnerships exist
- **Timing Suggestions**: When to reach out based on activity patterns

Generate multiple message variants:
- **Short Punchy**: Concise, direct, attention-grabbing
- **Credibility-first**: Lead with proof points and case studies
- **Insight-led / Value-first**: Lead with valuable insights or industry trends
- **Soft-ask / Low-friction**: Gentle approach with minimal commitment ask

Also generate complete sequences:
- **First Message**: Initial outreach
- **Follow-up 1**: First follow-up (2-3 days later)
- **Follow-up 2**: Second follow-up (1 week later)
- **Follow-up 3**: Final follow-up (2 weeks later)
- **Breakup Message**: Polite exit if no response

# OUTPUT SCHEMA(JSON)
{
            "fitScore": number,
            "fitReasons": ["reason1", "reason2"],
            "missingInfo": ["info1", "info2"],
            "triggerSignals": ["signal1", "signal2"],
            "mismatches": ["mismatch1", "mismatch2"],
            "influenceScore": number,
            "roleMapping": "string",
            "decisionReasoning": ["reason1"],
            "alternateTargets": ["Title 1 at Company", "Title 2 at Company"],
            "multiThreadTargets": ["Role 1", "Role 2", "Role 3"],
            "sharedContextScore": number,
            "sharedSignals": ["🎓 Same College: Stanford", "🏢 Ex-Google", "🌍 SF Bay Area"],
            "outreachStrategy": {
                "recommendedApproach": "Direct Pitch | Warm-up | Referral | Multi-threading | Partner-led",
                "rationale": "Why this approach",
                "timing": "When to reach out"
            },
            "messageVariants": {
                "shortPunchy": "text...",
                "credibilityFirst": "text...",
                "insightLed": "text...",
                "softAsk": "text..."
            },
            "messageSequence": {
                "firstMessage": "text...",
                "followUp1": "text...",
                "followUp2": "text...",
                "followUp3": "text...",
                "breakupMessage": "text..."
            },
            "connectionRequest": "text...",
            "coldEmail": "text...",
            "draftStrategy": "Brief description of the angle used",
            "signalsUsed": ["signal1", "signal2"],
            "confidence": "High | Medium | Low",
            "doSay": ["do say this", "do say that"],
            "dontSay": ["don't say this", "don't say that"]
        }
            `;

        log("Sending request to OpenAI...");
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${inputs.apiKey}`
            },
            body: JSON.stringify({
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "You are a JSON-speaking sales strategist." },
                    { role: "user", content: prompt }
                ],
                temperature: inputs.risk === 'Risky' ? 0.9 : 0.5,
                response_format: { type: "json_object" }
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error?.message || 'OpenAI API Error');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        try {
            return JSON.parse(content);
        } catch (e) {
            throw new Error("Failed to parse AI response as JSON.");
        }
    }

    // === Check for cached analysis ===
    async function checkCachedAnalysis(profileUrl) {
        const cacheKey = `analysis_${profileUrl}`;
        const cached = await chrome.storage.local.get(cacheKey);
        if (cached[cacheKey]) {
            log(`[Cache] Found cached analysis for ${profileUrl}`);
            return cached[cacheKey];
        }
        return null;
    }

    // === Regenerate Messages (Reuse Research) ===
    regenerateBtn.addEventListener('click', async () => {
        const inputData = {
            apiKey: apiKeyInput.value.trim(),
            goal: userGoalInput.value.trim(),
            icp: icpDefinitionInput.value.trim(),
            offer: offerDetailsInput.value.trim(),
            proof: proofPointsInput.value.trim(),
            risk: riskLevelInput.value,
            offerType: offerTypeInput.value
        };

        if (!inputData.apiKey) return updateStatus('Missing API Key');
        if (!inputData.goal) return updateStatus('Missing Goal');

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url.includes('linkedin.com/')) throw new Error('Go to LinkedIn Profile');

            const profileUrl = tab.url;
            const cached = await checkCachedAnalysis(profileUrl);
            
            if (!cached) {
                alert('No cached analysis found. Please run full analysis first.');
                return;
            }

            updateStatus("Regenerating messages...");
            log("[Regenerate] Using cached research data");
            log(`[Regenerate] Strategy: ${inputData.risk} | ${inputData.offerType}`);

            const senderData = (await chrome.storage.local.get('sender_profile_cache')).sender_profile_cache;

            // Only regenerate messages with new strategy
            updateStatus("Generating messages...");
            const analysis = await callOpenAI(
                inputData, 
                cached.profileData, 
                senderData, 
                cached.activity, 
                cached.company,
                cached.structuredProspect,
                cached.companyResearch,
                cached.postSummary
            );

            // Render the results
            renderResults(analysis, inputData.risk);
            showTab('tab-results');
            updateStatus("Messages regenerated!");
            log("Message regeneration complete.");

        } catch (e) {
            alert(e.message);
            updateStatus("Error");
            log(`Regeneration error: ${e.message}`);
        }
    });

    // === Analysis Logic ===
    analyzeBtn.addEventListener('click', async () => {
        const inputData = {
            apiKey: apiKeyInput.value.trim(),
            goal: userGoalInput.value.trim(),
            icp: icpDefinitionInput.value.trim(),
            offer: offerDetailsInput.value.trim(),
            proof: proofPointsInput.value.trim(),
            risk: riskLevelInput.value,
            offerType: offerTypeInput.value
        };

        if (!inputData.apiKey) return updateStatus('Missing API Key');
        if (!inputData.goal) return updateStatus('Missing Goal');

        const senderData = (await chrome.storage.local.get('sender_profile_cache')).sender_profile_cache;

        updateStatus("Connecting...");
        
        // Check for cached analysis
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url.includes('linkedin.com/')) {
            const cached = await checkCachedAnalysis(tab.url);
            if (cached) {
                log("[Cache] Found cached analysis - user can use 'Regenerate Messages' button");
                // Don't show regenerate button yet, wait until analysis completes
            }
        }

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url.includes('linkedin.com/')) throw new Error('Go to LinkedIn Profile');

            if (!(await ensureContentScript(tab.id))) throw new Error("Please refresh page");

            updateStatus("Scraping...");
            const response = await chrome.tabs.sendMessage(tab.id, { action: 'SCRAPE_PROFILE' });
            if (!response?.success) throw new Error("Scrape failed");

            updateStatus("Loading recent activity...");
            // Extract user handle from profile URL to construct recent activity URL
            const profileUrl = tab.url;
            const urlMatch = profileUrl.match(/linkedin\.com\/in\/([^\/]+)/);
            if (!urlMatch) throw new Error("Could not extract user handle from profile URL");
            
            const userHandle = urlMatch[1];
            const recentActivityUrl = `https://www.linkedin.com/in/${userHandle}/recent-activity/all/`;
            log(`[RecentActivity] Constructed URL: ${recentActivityUrl}`);
            
            // Open recent activity page in a new tab to avoid closing the popup
            const activityTab = await chrome.tabs.create({ 
                url: recentActivityUrl,
                active: false // Open in background
            });
            
            log(`[RecentActivity] Opened new tab: ${activityTab.id}`);
            
            // Wait for page to load
            await new Promise(resolve => setTimeout(resolve, 4000));
            
            // Wait for tab to be ready
            let tabReady = false;
            for (let i = 0; i < 10; i++) {
                try {
                    const currentTab = await chrome.tabs.get(activityTab.id);
                    if (currentTab.status === 'complete') {
                        tabReady = true;
                        break;
                    }
                } catch (e) {
                    log(`[RecentActivity] Waiting for tab... ${i + 1}/10`);
                }
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            
            if (!tabReady) {
                log("[RecentActivity] ⚠ Tab not ready, proceeding anyway");
            }
            
            // Inject content script into the new tab
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: activityTab.id },
                    files: ['scripts/content.js']
                });
                await new Promise(resolve => setTimeout(resolve, 1000)); // Wait for script to initialize
            } catch (e) {
                log(`[RecentActivity] ⚠ Could not inject script: ${e.message}`);
            }
            
            // Load posts from recent activity page
            let activity = { posts: [], likes: [], comments: [] };
            try {
                const activityResponse = await chrome.tabs.sendMessage(activityTab.id, { action: 'LOAD_RECENT_ACTIVITY' });
                if (activityResponse?.success && activityResponse.activity) {
                    activity = activityResponse.activity;
                    log(`[RecentActivity] ✓ Loaded ${activity.posts.length} posts`);
                } else {
                    log("[RecentActivity] ⚠ Failed to load activity, using empty activity");
                }
            } catch (e) {
                log(`[RecentActivity] ⚠ Error loading activity: ${e.message}`);
            }
            
            // Close the activity tab
            try {
                await chrome.tabs.remove(activityTab.id);
                log(`[RecentActivity] Closed activity tab`);
            } catch (e) {
                log(`[RecentActivity] ⚠ Could not close tab: ${e.message}`);
            }

            updateStatus("Extracting structured data...");
            log("[Extract] Prospect data length: " + response.data.length);
            log("[Extract] Activity: " + (activity ? `${activity.posts.length} posts` : 'none'));
            
            // Extract structured prospect data using GPT (including related profiles)
            const structuredProspect = await extractProspectWithGPT(
                response.data, 
                activity, 
                inputData.apiKey,
                response.relatedProfiles
            );
            log("[Extract] Structured prospect: " + JSON.stringify(structuredProspect));
            log("[Extract] ✓ Structured prospect extracted: " + structuredProspect.name);
            log("[Extract]   Company: " + (structuredProspect.currentPosition?.company || 'N/A'));
            log("[Extract]   Interests: " + (structuredProspect.interests?.topics?.join(', ') || 'N/A'));
            log("[Extract]   Related Profiles: " + (structuredProspect.relatedProfiles?.length || 0) + " extracted");
            //log("[Extract]   Related Profiles: " + (structuredProspect.relatedProfiles?.length || 0) + " extracted");

            updateStatus("Summarizing posts...");
            // Extract post URLs from activity
            const postUrls = (activity?.posts || [])
                .filter(p => p.url)
                .map(p => p.url)
                .slice(0, 10); // Increased to 10 posts since we have more now
            
            log(`[PostSummary] Found ${postUrls.length} post URLs from recent activity`);
            
            // Summarize posts and extract interests (with URL fetching)
            const postSummary = await summarizePostsAndExtractInterests(
                activity?.posts || [],
                postUrls,
                tab.id,
                inputData.apiKey
            );
            log("[PostSummary] Post analysis: " + (postSummary ? `Complete - ${postSummary.keyTopics?.length || 0} topics` : "Skipped"));
            log("[PostSummary] Post summary: " + JSON.stringify(postSummary));
            updateStatus("Researching companies...");
            // Research companies from prospect's experience
            const companyResearch = await researchCompanies(
                structuredProspect,
                inputData.offer,
                inputData.goal,
                inputData.icp,
                inputData.apiKey
            );
            log("[Research] Company research: " + (companyResearch ? "Complete" : "Skipped"));

            updateStatus("Analyzing related profiles...");
            // Analyze related profiles if available (from structured prospect or response)
            let relevantProfiles = [];
            const profilesToAnalyze = structuredProspect?.relatedProfiles || response.relatedProfiles || [];
            
            if (profilesToAnalyze.length > 0) {
                log(`[RelatedProfiles] Analyzing ${profilesToAnalyze.length} related profiles (from ${structuredProspect?.relatedProfiles ? 'GPT extraction' : 'content script'})...`);
                relevantProfiles = await analyzeRelatedProfiles(
                    profilesToAnalyze,
                    inputData.goal,
                    inputData.icp,
                    inputData.offer,
                    inputData.apiKey
                );
                log(`[RelatedProfiles] ✓ Found ${relevantProfiles.length} relevant profiles`);
            } else {
                log("[RelatedProfiles] No related profiles found");
            }

            updateStatus("Analyzing...");
            log("[CallOpenAI] Sender data length: " + (senderData ? senderData.length : 0));
            log("[CallOpenAI] Sender preview: " + (senderData ? senderData.substring(0, 300) : "N/A"));
            const analysis = await callOpenAI(
                inputData, 
                response.data, 
                senderData, 
                activity, 
                response.company,
                structuredProspect,
                companyResearch,
                postSummary
            );

            // Store analysis results for reuse
            const currentProfileUrl = tab.url;
            const cacheKey = `analysis_${currentProfileUrl}`;
            await chrome.storage.local.set({
                [cacheKey]: {
                    profileUrl: currentProfileUrl,
                    structuredProspect: structuredProspect,
                    postSummary: postSummary,
                    companyResearch: companyResearch,
                    activity: activity,
                    profileData: response.data,
                    company: response.company,
                    timestamp: new Date().toISOString()
                }
            });
            log(`[Cache] Stored analysis results for ${profileUrl}`);

            // Render the results
            renderResults(analysis, inputData.risk);
            
            // Render related profiles if available
            if (relevantProfiles && relevantProfiles.length > 0) {
                renderRelatedProfiles(relevantProfiles);
            } else {
                relatedProfilesContainer.innerHTML = '<p class="empty-state">No related profiles found or analyzed.</p>';
            }
            
            showTab('tab-results'); // Switch to results view
            updateStatus("Complete!");
            log("Analysis complete.");
            
            // Show regenerate button
            regenerateBtn.classList.remove('hidden');

        } catch (e) {
            alert(e.message);
            updateStatus("Error");
            log(`Analysis error: ${e.message}`);
        }
    });
})