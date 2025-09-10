console.log("login.js cargado y ejecutándose."); // Línea de depuración añadida

document.addEventListener('DOMContentLoaded', function() {
    // Obtener referencias al campo de contraseña y al icono del ojo
    const passwordField = document.getElementById('password');
    const togglePassword = document.getElementById('togglePassword');

    // Verificar que ambos elementos existen antes de añadir el event listener
    if (passwordField && togglePassword) {
        console.log("Elementos 'password' y 'togglePassword' encontrados."); // Línea de depuración
        // Añadir un 'event listener' para el clic en el icono del ojo
        togglePassword.addEventListener('click', function() {
            // Alternar el tipo de input entre 'password' y 'text'
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);

            // Alternar la clase del icono del ojo (abierto/cerrado)
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    } else {
        console.error("Error: No se encontraron los elementos 'password' o 'togglePassword' en el DOM.");
    }
});
