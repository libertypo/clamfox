const params = new URLSearchParams(window.location.search);
const url = params.get('url');
document.getElementById('target-url').textContent = url;
document.getElementById('reason').textContent = params.get('threat');

document.getElementById('go-back').addEventListener('click', () => {
    window.history.back();
});

document.getElementById('proceed-anyway').addEventListener('click', async (e) => {
    e.preventDefault();
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
        proceedBtn.style.display = 'none';

        const container = document.querySelector('.container');
        const warning = document.createElement('p');
        warning.style.color = '#ef4444';
        warning.style.fontSize = '12px';
        warning.style.marginTop = '20px';
        warning.style.padding = '10px';
        warning.style.background = 'rgba(239, 68, 68, 0.1)';
        warning.style.borderRadius = '8px';
        warning.style.border = '1px solid rgba(239, 68, 68, 0.2)';
        warning.textContent = "";
        const boldText = document.createElement("b");
        boldText.textContent = "Security Enforcement:";
        warning.appendChild(boldText);
        warning.appendChild(document.createTextNode(" This site is confirmed as malicious by global threat intelligence. Manual bypass is disabled for your protection."));
        container.appendChild(warning);
    }
}
