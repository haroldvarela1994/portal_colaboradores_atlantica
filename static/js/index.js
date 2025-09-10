  function toggleMenu() {
    const dropdown = document.getElementById("userDropdown");
    dropdown.style.display = (dropdown.style.display === "block") ? "none" : "block";
  }

  // Cierra el dropdown si se hace clic fuera
  document.addEventListener('click', function(event) {
    const menu = document.querySelector('.usuario-menu');
    const dropdown = document.getElementById('userDropdown');
    if (!menu.contains(event.target)) {
      dropdown.style.display = 'none';
    }
  });


// Botón para ocultar y mostrar la sidebar
function toggleSidebar() {
  document.querySelector('.sidebar').classList.toggle('sidebar-hidden');
}
