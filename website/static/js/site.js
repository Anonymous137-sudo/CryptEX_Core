document.querySelectorAll("[data-nav-toggle]").forEach(toggle => {
  toggle.addEventListener("click", () => {
    const nav = document.querySelector("[data-nav]");
    if (!nav) {
      return;
    }
    nav.classList.toggle("is-open");
  });
});
