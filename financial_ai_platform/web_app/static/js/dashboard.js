document.addEventListener('DOMContentLoaded', () => {
  fetchAndInitDashboard();
  expandCardSetup();
});

let networthData = null;
async function fetchAndInitDashboard() {
  try {
    const response = await fetch('/api/net-worth');
    const result = await response.json();
    if (result.status === 'success') {
      networthData = result.data;
      renderDashboardSummary(networthData);
    }
  } catch (e) {
    showDashboardError();
  }
}

function renderDashboardSummary(data) {
  document.getElementById('netWorthValue').textContent = formatCurrency(data.totalNetWorth);
  const cp = data.changePercent || 0;
  const changeEl = document.getElementById('netWorthChange');
  changeEl.textContent = `${cp >= 0 ? '+' : ''}${cp}% this month`;
  changeEl.className = cp >= 0 ? 'text-success' : 'text-danger';
  document.getElementById('assetsValue').textContent =
    formatCurrency(Object.values(data.assets).reduce((a, b) => a + b, 0));
  document.getElementById('liabilitiesValue').textContent =
    formatCurrency(Object.values(data.liabilities).reduce((a, b) => a + b, 0));
}

function expandCardSetup() {
  const setups = [
    { card: 'netWorthCard', details: 'netWorthDetails', type: 'networth' },
    { card: 'assetsCard', details: 'assetsDetails', type: 'assets' },
    { card: 'liabilitiesCard', details: 'liabilitiesDetails', type: 'liabilities' }
  ];
  setups.forEach(({ card, details, type }) => {
    let chartObj = null;
    document.getElementById(card).addEventListener('click', () => {
      var det = document.getElementById(details);
      if (!det.classList.contains('show')) {
        new bootstrap.Collapse(det, { toggle: true });
        if (!chartObj && networthData) {
          if (type === 'networth') renderNetWorthChartTable(networthData);
          if (type === 'assets') renderAssetsChartTable(networthData.assets);
          if (type === 'liabilities') renderLiabilitiesChartTable(networthData.liabilities);
        }
      }
    });
  });
}

function renderNetWorthChartTable(data) {
  const ctx = document.getElementById('netWorthChart').getContext('2d');
  const assets = data.assets || {};
  const liabilities = data.liabilities || {};
  const labels = [...Object.keys(assets), ...Object.keys(liabilities)];
  const values = [...Object.values(assets), ...Object.values(liabilities).map(v => -v)];
  const colors = getChartColors(labels.length);
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels.map(humanLabel),
      datasets: [{ data: values.map(Math.abs), backgroundColor: colors }]
    },
    options: { plugins: { legend: { position: 'bottom' } } }
  });
  const rows = [];
  Object.entries(assets).forEach(([k, v]) =>
    rows.push(`<tr><td>${humanLabel(k)} (Asset)</td><td class="text-end">${formatCurrency(v)}</td></tr>`));
  Object.entries(liabilities).forEach(([k, v]) =>
    rows.push(`<tr><td>${humanLabel(k)} (Liability)</td><td class="text-end">-${formatCurrency(v)}</td></tr>`));
  document.getElementById('netWorthTable').innerHTML = rows.join('');
}
function renderAssetsChartTable(assets) {
  const ctx = document.getElementById('assetsChart').getContext('2d');
  const keys = Object.keys(assets);
  const values = Object.values(assets);
  const colors = getChartColors(keys.length);
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: keys.map(humanLabel),
      datasets: [{ data: values, backgroundColor: colors }]
    },
    options: { plugins: { legend: { position: 'bottom' } } }
  });
  document.getElementById('assetsTable').innerHTML =
    keys.map((k, i) => `<tr><td>${humanLabel(k)}</td><td class="text-end">${formatCurrency(values[i])}</td></tr>`).join('');
}
function renderLiabilitiesChartTable(liabilities) {
  const ctx = document.getElementById('liabilitiesChart').getContext('2d');
  const keys = Object.keys(liabilities);
  const values = Object.values(liabilities).map(Math.abs);
  const colors = ['#ffc107', '#fd7e14', '#dc3545', '#adb5bd', '#6f42c1'].slice(0, keys.length);
  new Chart(ctx, {
    type: 'pie',
    data: {
      labels: keys.map(humanLabel),
      datasets: [{ data: values, backgroundColor: colors }]
    },
    options: { plugins: { legend: { position: 'bottom' } } }
  });
  document.getElementById('liabilitiesTable').innerHTML =
    keys.map((k, i) => `<tr><td>${humanLabel(k)}</td><td class="text-end">-${formatCurrency(values[i])}</td></tr>`).join('');
}
function getChartColors(ct) { 
  return ['#007bff','#28a745','#17a2b8','#6610f2','#e83e8c','#20c997','#6f42c1','#ffc107','#fd7e14','#dc3545','#00b894'].slice(0, ct);
}
function humanLabel(key) { 
  return key.replace(/([A-Z])/g, ' $1').replace(/^./, s=>s.toUpperCase());
}
function formatCurrency(amount) {
  if(typeof amount!=='number') return '₹0'; 
  return new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR',minimumFractionDigits:0}).format(amount);
}
function showDashboardError() {
  ['netWorthValue','assetsValue','liabilitiesValue'].forEach(id => {
    document.getElementById(id).textContent = 'Error';
  });
}
