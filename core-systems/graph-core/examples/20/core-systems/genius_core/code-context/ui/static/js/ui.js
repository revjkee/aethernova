// genius-core/code-context/ui/static/js/ui.js

document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initGraphPanel();
  initTooltips();
  initThemeToggle();
  initResizeHandlers();
});

function initNav() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', e => {
      const target = e.currentTarget.getAttribute('data-target');
      document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
      document.getElementById(target).classList.remove('hidden');
    });
  });
}

function initGraphPanel() {
  const canvas = document.getElementById('code-graph');
  if (!canvas || !window.renderGraph) return;

  const ctx = canvas.getContext('2d');
  window.renderGraph(ctx, canvas.width, canvas.height);

  window.addEventListener('resize', () => {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    window.renderGraph(ctx, canvas.width, canvas.height);
  });
}

function initTooltips() {
  const tooltip = document.getElementById('tooltip');
  if (!tooltip) return;

  document.querySelectorAll('[data-tooltip]').forEach(el => {
    el.addEventListener('mouseenter', e => {
      tooltip.textContent = e.currentTarget.getAttribute('data-tooltip');
      tooltip.style.opacity = '1';
    });
    el.addEventListener('mousemove', e => {
      tooltip.style.top = `${e.pageY + 12}px`;
      tooltip.style.left = `${e.pageX + 12}px`;
    });
    el.addEventListener('mouseleave', () => {
      tooltip.style.opacity = '0';
    });
  });
}

function initThemeToggle() {
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;

  toggle.addEventListener('click', () => {
    document.body.classList.toggle('dark');
    localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light');
  });

  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark') {
    document.body.classList.add('dark');
  }
}

function initResizeHandlers() {
  const panels = document.querySelectorAll('.resizable');
  panels.forEach(panel => {
    const handle = panel.querySelector('.resize-handle');
    if (!handle) return;

    let isDragging = false;
    handle.addEventListener('mousedown', e => {
      isDragging = true;
      document.body.classList.add('resizing');
    });

    window.addEventListener('mousemove', e => {
      if (!isDragging) return;
      const newWidth = e.pageX - panel.offsetLeft;
      panel.style.width = `${newWidth}px`;
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
      document.body.classList.remove('resizing');
    });
  });
}
