const params = new URLSearchParams(window.location.search);
const url = params.get('url');
document.getElementById('target-url').textContent = url || "";
document.getElementById('reason').textContent = params.get('threat');

function isSafeRedirectTarget(candidate) {
    try {
        const parsed = new URL(candidate);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

document.getElementById('go-back').addEventListener('click', () => {
    window.history.back();
});

document.getElementById('proceed-anyway').addEventListener('click', async (e) => {
    e.preventDefault();
    if (!isSafeRedirectTarget(url)) {
        return;
    }
    if (confirm("This site is dangerous. Are you absolutely sure you want to proceed?")) {
        try {
            const domain = new URL(url).hostname;
            await browser.runtime.sendMessage({ action: "bypass_domain", domain: domain });
        } catch (err) { }
        window.location.href = url;
    }
});

const isConfirmed = params.get('confirmed') === '1';
if (isConfirmed) {
    const proceedBtn = document.getElementById('proceed-anyway');
    if (proceedBtn) {
        proceedBtn.classList.add('hidden');

        const container = document.querySelector('.container');
        const warning = document.createElement('p');
        warning.className = 'confirmed-warning';
        warning.textContent = "";
        const boldText = document.createElement("b");
        boldText.textContent = "Security Enforcement:";
        warning.appendChild(boldText);
        warning.appendChild(document.createTextNode(" This site is confirmed as malicious by global threat intelligence. Manual bypass is disabled for your protection."));
        container.appendChild(warning);
    }
}
