const params = new URLSearchParams(window.location.search);
const url = params.get('url');
document.getElementById('target-url').textContent = url;
document.getElementById('reason').textContent = params.get('threat');

document.getElementById('go-back').addEventListener('click', () => {
    window.history.back();
});

document.getElementById('proceed-anyway').addEventListener('click', (e) => {
    e.preventDefault();
    if (confirm("This site is dangerous. Are you absolutely sure you want to proceed?")) {
        window.location.href = url;
    }
});
