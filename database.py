from peewee import *
import datetime
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from flask_login import UserMixin

# Cargar variables de entorno
load_dotenv()

# Variables desde el .env
DB_NAME = os.getenv("database")
DB_USER = os.getenv("user")
DB_PASSWORD = os.getenv("password")
DB_HOST = os.getenv("host")
DB_PORT = int(os.getenv("port"))

# Conexión a la base de datos con las variables correctas
db = MySQLDatabase(
    database=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)
# Clase base modelo para Peewee
class BaseModel(Model):
    class Meta:
        database = db
        
# Tabla Estado       
class Estado(BaseModel):
    id_estado = AutoField(primary_key=True)
    estado = CharField(choices=[{'Activo', 'Inactivo', 'Suspendido', 'Eliminado'}], default='Activo')
    
    class Meta:
        table_name = 'estado'

# Tabla Roles       
class Roles(BaseModel):
    id_rol = AutoField(primary_key=True)
    rol = CharField(choices=[{'Administrador', 'Gerente General', 'RRHH', 'Empleado (a)', 'Jurídica'}], default='Usuario') 
    descripcion = CharField(max_length=500)
    
    class Meta:
        table_name = 'roles'

# Tabla Usuarios
class Usuarios(BaseModel, UserMixin):
    id_usuario = AutoField(primary_key=True)
    numero_id = CharField()
    email = CharField(unique=True)
    clave = CharField(max_length=255)
    nombres_usuario = CharField()
    apellidos_usuario = CharField()
    fecha_nacimiento = DateTimeField()
    direccion = CharField(max_length=255)
    telefono = CharField(max_length=255)
    fecha_registro = DateTimeField(default=datetime.datetime.now)
    rol = ForeignKeyField(Roles, backref='usuarios')
    estado = ForeignKeyField(Estado, backref='usuarios')
    foto = CharField()

    class Meta:
        table_name = 'usuarios'

    def __str__(self):
        return f"Usuario(ID: {self.id_usuario}, Email: {self.email})"

    def get_id(self):
        return str(self.id_usuario)
        
# Tabla Noticias            
class Noticias(BaseModel):
    id_noticias = AutoField(primary_key=True)
    titulo = CharField(max_length=255)
    contexto = CharField()
    fecha_noticia = DateTimeField(default=datetime.datetime.now)
    autor = ForeignKeyField(Usuarios, backref='noticias')
    imagen = CharField(null=True)
    
    class Meta:
        table_name = 'noticias'

class Tipo_Faltas(BaseModel):
    id_tipo_falta = AutoField(primary_key=True)
    tipo_falta = CharField(choices=[{'Leve', 'Grave'}], default='Leve')
    
    class Meta:
        table_name = 'tipo_faltas'

class Faltas(BaseModel):
    id_falta = AutoField(primary_key=True)
    tipo_falta = ForeignKeyField(Tipo_Faltas, backref='faltas')
    falta = CharField(max_length=255)
    
    class Meta:
        table_name = 'faltas'

class Disciplinarios(BaseModel):
    id_citacion = AutoField(primary_key=True)
    nombres_usuario = ForeignKeyField(Usuarios, backref='disciplinarios')
    apellidos_usuario = ForeignKeyField(Usuarios, backref='disciplinarios')
    tipo_falta = ForeignKeyField(Tipo_Faltas, backref='disciplinarios')
    fecha_citacion = DateTimeField()
    hora_citacion = TimeField()
    lugar = CharField(max_length=255)
    modalidad = CharField(choices=[('Presencial', 'Presencial'), ('Virtual', 'Virtual')])
    autor = ForeignKeyField(Usuarios, backref='disciplinarios')
    fecha = DateTimeField(default=datetime.datetime.now)
    firma = CharField(max_length=64)
    
    class Meta:
        table_name = 'disciplinarios'

class Descargos(BaseModel):
    id_descargo = AutoField(primary_key=True)
    id_citacion = ForeignKeyField(Disciplinarios, backref='descargos')
    fecha_actual = DateTimeField(default=datetime.datetime.now)
    hora_inicio = TimeField()
    hora_final = TimeField()
    archivo = CharField(max_length=255)
    observaciones = CharField(max_length=500)

try:
    db.connect()
    print("¡Conexión a la base de datos MySQL exitosa con PeeWee!")
    db.create_tables([Estado, Roles, Usuarios, Noticias, Tipo_Faltas, Faltas, Disciplinarios, Descargos], safe=True)
    print("Tablas verificadas/creadas en la base de datos.")
except Exception as e:
    print(f"Ocurrió un error al crear las tablas: {e}")

    # Mover la lógica de creación/obtención del administrador aquí, después de crear las tablas
    try:
        # Comprobamos si el rol 'Administrador' existe, sino lo creamos
        rol_admin = Roles.get(Roles.rol == 'Administrador')
        print("Rol Administrador encontrado.")
    except DoesNotExist:
        try:
            rol_admin = Roles.create(rol='Administrador', descripcion='Rol con todos los privilegios')
            print("Rol Administrador creado.")
        except Exception as e:
            print(f"Error al crear el rol Administrador: {e}")

    try:
        # Comprobamos si el estado 'Activo' existe, sino lo creamos
        estado_activo = Estado.get(Estado.estado == 'Activo')
        print("Estado Activo encontrado.")
    except DoesNotExist:
        try:
            estado_activo = Estado.create(estado='Activo')
            print("Estado Activo creado.")
        except Exception as e:
            print(f"Error al crear el estado Activo: {e}")

    try:
        # Buscamos si el administrador ya existe
        admin_check = Usuarios.get(Usuarios.email == 'haroldvarela1@gmail.com')
        print(f"Usuario administrador encontrado: {admin_check}")  # Debugging statement
        if not admin_check.clave.startswith('$2b$'):  # Verificamos si la contraseña no está hasheada
            print("Actualizando la contraseña del administrador")  # Debugging statement
            admin_check.clave = generate_password_hash('Rossiya1991')
            admin_check.save()
            print("Contraseña del administrador actualizada.")
    except DoesNotExist:
        print("El usuario administrador no existe, procediendo a crearlo...")  # Debugging statement
        try:
            # Si no existe el administrador, lo creamos
            print("Creando el usuario administrador...")  # Debugging statement
            Usuarios.create(
                numero_id='0000000000',
                email='haroldvarela1@gmail.com',
                clave=generate_password_hash('Rossiya1991'),
                nombres_usuario='Administrador',
                apellidos_usuario='Atlántica',
                fecha_nacimiento=datetime.datetime(2010, 1, 1),
                direccion='N/A',
                telefono='N/A',
                rol=rol_admin,
                estado=estado_activo,
                foto='N/A'
            )
            print("Administrador creado correctamente.")
        except Exception as e:
            print(f"Error al crear el administrador: {e}")
    except Exception as e:
        print(f"Error al buscar el usuario: {e}")


# Inicializar roles predeterminados
def inicializar_roles():
    roles_data = [
        {'rol': 'Administrador', 'descripcion': 'Rol con todos los privilegios'},
        {'rol': 'Empleado', 'descripcion': 'Rol con permisos de visualizar nómina, gestionar las solicitudes y disciplinarios'},
        {'rol': 'Gerente General', 'descripcion': 'Rol con varios privilegios, excepto la gestión de usuarios'},
        {'rol': 'RRHH', 'descripcion': 'Rol con permisos para gestionar usuarios con excepción de crear, realizar memoriales y ver nómina'},
        {'rol': 'Jurídica', 'descripcion': 'Rol con permisos de consulta y gestión de documentos legales, incluyendo la revisión de contratos y políticas, así como el tema disciplinario'},
    ]

    try:
        with db.atomic():
            # Primero obtenemos todos los roles existentes
            roles_existentes = {r.rol: r for r in Roles.select()}
            
            for rol_info in roles_data:
                if rol_info['rol'] in roles_existentes:
                    # Actualizar registro existente
                    Roles.update(descripcion=rol_info['descripcion'])\
                        .where(Roles.rol == rol_info['rol'])\
                        .execute()
                else:
                    # Crear nuevo registro solo si no existe
                    Roles.create(**rol_info)
                    
        print("✅ Tabla de roles actualizada completamente")
        
    except Exception as e:
        print(f"❌ Error crítico: {str(e)}")
        raise

def inicializar_estados():
    estados_data = [
        {'estado': 'Activo'},
        {'estado': 'Inactivo'},
    ]

    try:
        with db.atomic():
            # Primero obtenemos todos los estados existentes
            estados_existentes = {e.estado: e for e in Estado.select()}

            for estado_info in estados_data:
                if estado_info['estado'] in estados_existentes:
                    # Actualizar registro existente
                    Estado.update(**estado_info)\
                        .where(Estado.estado == estado_info['estado'])\
                        .execute()
                else:
                    # Crear nuevo registro solo si no existe
                    Estado.create(**estado_info)

        print("✅ Tabla de estados actualizada completamente")

    except Exception as e:
        print(f"❌ Error crítico: {str(e)}")
        raise

inicializar_roles()
inicializar_estados()