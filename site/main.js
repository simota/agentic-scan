// Progressive enhancement only: the page reads fully without this file.
const TEXT = {
  en: { copy: "Copy", copied: "Copied", toast: "Command copied", failed: "Couldn't copy. Select the text and copy it." },
  ja: { copy: "コピー", copied: "コピー済み", toast: "コマンドをコピーしました", failed: "コピーできませんでした。選択してコピーしてください" },
};

document.addEventListener("DOMContentLoaded", () => {
  const t = TEXT[document.documentElement.lang] || TEXT.en;
  const toast = document.querySelector(".toast");
  let toastTimer;
  const say = (text) => {
    toast.textContent = text;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 1800);
  };

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        button.textContent = t.copied;
        say(t.toast);
        setTimeout(() => (button.textContent = t.copy), 1800);
      } catch {
        say(t.failed);
      }
    });
  });

  // Tabs (WAI-ARIA tabs pattern, automatic activation)
  document.querySelectorAll("[data-tabs]").forEach((root) => {
    const tabs = [...root.querySelectorAll('[role="tab"]')];
    const select = (tab, focus) => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    };
    select(tabs.find((t) => t.getAttribute("aria-selected") === "true") || tabs[0], false);
    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => select(tab, false));
      tab.addEventListener("keydown", (e) => {
        const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
        if (next === undefined) return;
        e.preventDefault();
        select(tabs[(next + tabs.length) % tabs.length], true);
      });
    });
  });
});
