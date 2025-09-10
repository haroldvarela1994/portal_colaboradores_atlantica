CREATE DATABASE usuarios;

CREATE TABLE usuario (
	id_empleado INT (10) PRIMARY KEY,
	numero_identificacion INT (10),
	email VARCHAR (50),
	clave VARCHAR (50),
	nombres_empleado VARCHAR (50),
	apellidos_empleado VARCHAR (50),
	direccion VARCHAR (100),
	telefono VARCHAR (50),
	fecha_ingreso DATE,
	id_rol INT (10),
	FOREIGN KEY roles (id_rol) REFERENCES roles(id_rol),
	estado_empleado VARCHAR (100),
	foto_perfil VARCHAR (500)
);
	
CREATE TABLE roles (
	id rol INT (10) PRIMARY KEY,
	rol VARCHAR (50),
	descripcion VARCHAR (500)
);

