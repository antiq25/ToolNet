// Show the loader when the page starts loading
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('loader').style.display = 'flex';
});

// Hide the loader when the page finishes loading
window.addEventListener('load', function() {
  document.getElementById('loader').style.display = 'none';
});

