document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;

    const value = button.dataset.copy || "";
    const status = document.querySelector(".copy-status");
    try {
        await navigator.clipboard.writeText(value);
        if (status) status.textContent = "Copied to clipboard.";
        const previous = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => { button.textContent = previous; }, 1500);
    } catch (_error) {
        if (status) status.textContent = "Clipboard access is unavailable in this browser context.";
    }
});
