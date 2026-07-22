async function refreshDashboard() {
  const response = await fetch('/dashboard');
  const data = await response.json();
  const summary = data.summary;
  const dashboard = document.getElementById('dashboard');
  const table = document.getElementById('event-table');

  dashboard.innerHTML = `
    <div class="card"><strong>Total Events</strong><div>${summary.total}</div></div>
    <div class="card"><strong>Blocked</strong><div>${summary.blocked}</div></div>
    <div class="card"><strong>Rate Limited</strong><div>${summary.rate_limited}</div></div>
    <div class="card"><strong>Categories</strong><div>${Object.entries(summary.categories).map(([k, v]) => `${k}: ${v}`).join('<br>')}</div></div>
  `;

  table.innerHTML = data.events.slice().reverse().map(event => `
    <tr>
      <td>${event.timestamp}</td>
      <td>${event.ip}</td>
      <td>${event.category}</td>
      <td>${event.result}</td>
    </tr>
  `).join('');
}

window.addEventListener('DOMContentLoaded', () => {
  refreshDashboard();

  document.getElementById('demo-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    const response = await fetch('/submit', {
      method: 'POST',
      body: formData,
    });
    const data = await response.json();
    const result = document.getElementById('result');
    result.textContent = `${data.result.toUpperCase()} — ${data.category}`;
    result.style.color = data.result === 'allowed' ? '#7bed9f' : '#ff7675';
    refreshDashboard();
  });
});
