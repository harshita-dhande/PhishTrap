// PhishTrap Gmail Bridge Content Script
(function () {
  const PHISHTRAP_BASE_URL = "http://127.0.0.1:8080";

  function injectPhishTrapLinks() {
    // 1. Find all label chips matching PhishTrap in email row or email header
    const elements = document.querySelectorAll("div[title*='PhishTrap'], span[title*='PhishTrap'], div[aria-label*='PhishTrap']");
    elements.forEach((el) => {
      if (el.dataset.phishtrapEnhanced) return;
      el.dataset.phishtrapEnhanced = "true";
      el.style.cursor = "pointer";
      el.title = "Click to open PhishTrap Security Report (opens in new tab)";

      el.addEventListener("click", (e) => {
        e.stopPropagation();
        window.open(PHISHTRAP_BASE_URL + "/?tab=gmail", "_blank");
      });
    });

    // 2. In open email view, if email has PhishTrap verdict or draft, add quick banner button
    const subjectHeaders = document.querySelectorAll("h2[data-thread-perm-id]");
    subjectHeaders.forEach((h2) => {
      if (h2.dataset.phishtrapBanner) return;
      h2.dataset.phishtrapBanner = "true";

      const btn = document.createElement("button");
      btn.className = "phishtrap-btn";
      btn.innerHTML = "🛡️ PhishTrap Report";
      btn.title = "Open PhishTrap Threat Dashboard for this email";
      btn.onclick = () => {
        window.open(PHISHTRAP_BASE_URL, "_blank");
      };

      h2.parentNode.insertBefore(btn, h2.nextSibling);
    });
  }

  // Poll DOM for Gmail's single page app changes
  setInterval(injectPhishTrapLinks, 1500);
})();
