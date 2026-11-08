import { processInput } from './tool.ts';
import { initTheme } from './theme.ts';
import { initModals } from './modals.ts';
import { showToast } from './toast.ts';
import { auditCookies } from './cookies.ts';
import { auditVault } from './vault.ts';

// Initialize theme and modals on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initModals();
  auditCookies();
  auditVault();

  const inputEl = document.getElementById('app-input') as HTMLTextAreaElement;
  const processBtn = document.getElementById('action-process') as HTMLButtonElement;
  const clearBtn = document.getElementById('action-clear') as HTMLButtonElement;
  const copyBtn = document.getElementById('action-copy') as HTMLButtonElement;
  const outputRegion = document.getElementById('output-region') as HTMLElement;

  if (!inputEl || !processBtn || !clearBtn || !copyBtn || !outputRegion) {
    console.error('Required DOM elements not found');
    return;
  }

  // Process button handler
  processBtn.addEventListener('click', () => {
    const input = inputEl.value.trim();
    if (!input) {
      showToast('Please enter a JWT token');
      return;
    }

    const res = processInput(input);
    if (res.success) {
      // Escape HTML for safe rendering
      const escaped = res.data
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
      outputRegion.innerHTML = `<pre><code>${escaped}</code></pre>`;
      if (res.warnings && res.warnings.length > 0) {
        const warningHtml = res.warnings.map(w => `<div class="warning">⚠ ${w}</div>`).join('');
        outputRegion.innerHTML += `<div class="warnings">${warningHtml}</div>`;
      }
      showToast('Completed successfully!');
    } else {
      outputRegion.innerHTML = `<pre class="error">Error: ${res.error || 'Processing failed'}</pre>`;
      showToast('Error: ' + (res.error || 'Processing failed'));
    }
  });

  // Clear button handler
  clearBtn.addEventListener('click', () => {
    inputEl.value = '';
    outputRegion.innerHTML = '<p class="placeholder">Decoded JWT will appear here...</p>';
    showToast('Cleared');
  });

  // Copy button handler
  copyBtn.addEventListener('click', async () => {
    const text = outputRegion.textContent || '';
    if (!text || text.startsWith('Decoded JWT will appear')) {
      showToast('Nothing to copy');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      showToast('Copied to clipboard!');
    } catch (err) {
      showToast('Copy failed: ' + (err instanceof Error ? err.message : String(err)));
    }
  });

  // Auto-hydrate from URL query parameters (?q=, ?cron=, ?preset=, ?input=, etc.) & Share button
  try {
    const params = new URLSearchParams(window.location.search);
    const queryVal = params.get('q') || params.get('cron') || params.get('preset') || params.get('input') || params.get('pattern') || params.get('dialect') || params.get('mode');
    if (queryVal && inputEl) {
      inputEl.value = queryVal;
      processBtn.click();
    }
  } catch (e) {
    // ignore
  }

  // Inject 🔗 Share Permalink button next to action buttons if not present
  try {
    const actionsContainer = processBtn.parentElement;
    if (actionsContainer && !document.getElementById('action-share')) {
      const shareBtn = document.createElement('button');
      shareBtn.id = 'action-share';
      shareBtn.type = 'button';
      shareBtn.className = copyBtn.className || 'btn';
      shareBtn.textContent = '🔗 Share Link';
      shareBtn.style.marginLeft = '8px';
      shareBtn.addEventListener('click', async () => {
        const val = inputEl.value.trim();
        const url = new URL(window.location.origin + window.location.pathname);
        if (val) {
          url.searchParams.set('q', val);
        }
        try {
          await navigator.clipboard.writeText(url.toString());
          showToast('Shareable permalink copied to clipboard!');
        } catch {
          showToast('Failed to copy permalink');
        }
      });
      actionsContainer.appendChild(shareBtn);
    }
  } catch (e) {
    // ignore
  }
});

