from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from peewee import DoesNotExist
from database import *
import os
import re
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime

load_dotenv()

clave_secreta = os.getenv('SECRET_KEY')
CARPETA_CARGA = 'static/uploads'
EXT_ADMITIDAS_IMAGEN = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = clave_secreta
app.config['UPLOAD_FOLDER'] = CARPETA_CARGA
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in EXT_ADMITIDAS_IMAGEN

def rol_requerido(*roles_permitidos):
    def decorator(func):
        @wraps(func)
        def wrapper_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            
            if current_user.rol.rol not in roles_permitidos:
                flash('No tienes permisos para acceder a esta sección', 'error')
                return redirect(url_for('index'))
            
            return func(*args, **kwargs)
        return wrapper_view
    return decorator

@login_manager.user_loader
def cargar_usuario(user_id):
    try:
        return Usuarios.get(Usuarios.id_usuario == user_id)
    except DoesNotExist:
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        clave = request.form.get('clave', '').strip()

        if not email or not clave:
            flash('Por favor, ingresa tu correo y contraseña', 'error')
            return render_template('login.html')

        try:
            user_db = Usuarios.get(Usuarios.email == email)
            
            if check_password_hash(user_db.clave, clave):
                login_user(user_db)
                flash('¡Inicio de sesión exitoso!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Credenciales incorrectas', 'error')
        except DoesNotExist:
            flash('Usuario no encontrado', 'error')
        except Exception as e:
            flash(f'Error al iniciar sesión: {str(e)}', 'error')
            
    return render_template('login.html')

@app.route('/index')
@login_required
def index():
    noticias = Noticias.select().order_by(Noticias.fecha_noticia.desc()).limit(2)
    return render_template('index.html', noticias=noticias)

@app.route('/admin/usuarios')
@login_required
@rol_requerido('Administrador', 'Gerente General')
def gestion_usuarios():
    # Obtener parámetros de filtrado
    estado_filter = request.args.get('estado', '')
    rol_filter = request.args.get('rol', '')
    search_term = request.args.get('search', '')
    
    # Consulta base
    query = (Usuarios
             .select(Usuarios, Roles.rol, Estado.estado)
             .join(Roles, on=(Usuarios.rol == Roles.id_rol))
             .join(Estado, on=(Usuarios.estado == Estado.id_estado)))
    
    # Aplicar filtros
    if estado_filter:
        query = query.where(Estado.estado == estado_filter)
    
    if rol_filter:
        query = query.where(Roles.rol == rol_filter)
    
    if search_term:
        search_term = f"%{search_term}%"
        query = query.where(
            (Usuarios.nombres_usuario ** search_term) |
            (Usuarios.apellidos_usuario ** search_term) |
            (Usuarios.email ** search_term) |
            (Usuarios.numero_id ** search_term)
        )
    
    usuarios = query
    
    estados = Estado.select()
    roles = Roles.select()
    
    return render_template('admin/usuarios.html', 
                         usuarios=usuarios,
                         estados=estados,
                         roles=roles,
                         current_filters={
                             'estado': estado_filter,
                             'rol': rol_filter,
                             'search': search_term.replace('%', '') if search_term else ''
                         })
@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
@rol_requerido('Administrador')
def crear_usuario():
    if request.method == 'POST':
        try:
            required_fields = ['numero_id', 'email', 'clave', 'nombres_usuario', 'rol_id', 'estado_id']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f"El campo {field} es obligatorio", "error")
                    return redirect(url_for('crear_usuario'))

            fecha_nacimiento = datetime.strptime(request.form['fecha_nacimiento'], '%Y-%m-%d') if request.form.get('fecha_nacimiento') else None
            
            nuevo_usuario = Usuarios.create(
                numero_id=request.form['numero_id'],
                email=request.form['email'],
                clave=generate_password_hash(request.form['clave']),
                nombres_usuario=request.form['nombres_usuario'],
                apellidos_usuario=request.form.get('apellidos_usuario', ''),
                fecha_nacimiento=datetime.strptime(request.form['fecha_nacimiento'], '%Y-%m-%d') if request.form.get('fecha_nacimiento') else None,
                direccion=request.form.get('direccion', ''),
                telefono=request.form.get('telefono', ''),
                fecha_registro=datetime.utcnow(),
                rol=Roles.get(Roles.id_rol == request.form['rol_id']),
                estado=Estado.get(Estado.id_estado == request.form['estado_id']),
                foto=secure_filename(request.files['foto'].filename) if 'foto' in request.files else None
            )
            
            flash("Usuario creado correctamente", "success")
            return redirect(url_for('gestion_usuarios'))
            
        except Exception as e:
            flash(f"Error al crear usuario: {str(e)}", "error")
            return redirect(url_for('crear_usuario'))
    
    return render_template('admin/crear_usuario.html', roles=Roles.select(), estados=Estado.select())

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
@rol_requerido('Administrador')
def editar_usuario(user_id):
    try:
        usuario = Usuarios.get(Usuarios.id_usuario == user_id)
    except Usuarios.DoesNotExist:
        abort(404)

    if request.method == 'GET':
        roles = Roles.select()
        estados = Estado.select()
        return render_template('admin/modificar_usuario.html', 
                            usuario=usuario,
                            roles=roles,
                            estados=estados)
    
    if request.method == 'POST':
        try:
            required_fields = {
                'numero_id': request.form.get('numero_id', '').strip(),
                'nombres_usuario': request.form.get('nombres_usuario', '').strip(),
                'apellidos_usuario': request.form.get('apellidos_usuario', '').strip(),
                'email': request.form.get('email', '').strip(),
                'rol_id': request.form.get('rol_id'),
                'estado_id': request.form.get('estado_id')
            }
            
            for field, value in required_fields.items():
                if not value:
                    flash(f"El campo {field.replace('_', ' ').title()} es obligatorio", "error")
                    return redirect(url_for('editar_usuario', user_id=user_id))
            
            if not re.match(r"[^@]+@[^@]+\.[^@]+", required_fields['email']):
                flash("El formato del email no es válido", "error")
                return redirect(url_for('editar_usuario', user_id=user_id))
            
            telefono = request.form.get('telefono', '').strip()
            direccion = request.form.get('direccion', '').strip()
            clave = request.form.get('clave', '').strip()
            
            fecha_nacimiento_str = request.form.get('fecha_nacimiento')
            fecha_nacimiento = None
            if fecha_nacimiento_str:
                try:
                    fecha_nacimiento = datetime.strptime(fecha_nacimiento_str, '%Y-%m-%d')
                except ValueError:
                    flash("Formato de fecha inválido. Use YYYY-MM-DD", "error")
                    return redirect(url_for('editar_usuario', user_id=user_id))
            
            foto = None
            if 'foto' in request.files:
                file = request.files['foto']
                if file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    foto = filename
                    if usuario.foto and usuario.foto != 'N/A':
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], usuario.foto))
                        except OSError:
                            pass
            
            usuario.numero_id = required_fields['numero_id']
            usuario.nombres_usuario = required_fields['nombres_usuario']
            usuario.apellidos_usuario = required_fields['apellidos_usuario']
            usuario.email = required_fields['email']
            usuario.telefono = telefono
            usuario.direccion = direccion
            usuario.fecha_nacimiento = fecha_nacimiento
            
            if foto:
                usuario.foto = foto
            
            if clave:
                usuario.clave = generate_password_hash(clave)
            
            usuario.rol = Roles.get(Roles.id_rol == required_fields['rol_id'])
            usuario.estado = Estado.get(Estado.id_estado == required_fields['estado_id'])
            
            usuario.save()
            
            flash("Usuario actualizado correctamente", "success")
            return redirect(url_for('gestion_usuarios'))
            
        except DoesNotExist:
            flash("El rol o estado seleccionado no existe", "error")
            return redirect(url_for('editar_usuario', user_id=user_id))
        except Exception as e:
            app.logger.error(f"Error al actualizar usuario: {str(e)}")
            flash("Ocurrió un error al actualizar el usuario", "error")
            return redirect(url_for('editar_usuario', user_id=user_id))

@app.route('/admin/usuarios/cambiar-estado/<int:user_id>', methods=['POST'])
@login_required
@rol_requerido('Administrador')
def cambiar_estado_usuario(user_id):
    try:
        usuario = Usuarios.get(Usuarios.id_usuario == user_id)
        
        if usuario == current_user:
            flash("No puedes cambiar el estado de tu propio usuario", "error")
            return redirect(url_for('gestion_usuarios'))
        
        if usuario.estado.estado == 'Activo':
            nuevo_estado = Estado.get(Estado.estado == 'Inactivo')
            mensaje = "desactivado"
            clase_boton = "btn-desactivar"
        else:
            nuevo_estado = Estado.get(Estado.estado == 'Activo')
            mensaje = "activado"
            clase_boton = "btn-activar"
        
        usuario.estado = nuevo_estado
        usuario.save()
        
        flash(f"Usuario {mensaje} correctamente", "success")
        
    except DoesNotExist:
        flash("El usuario no existe", "error")
    except Exception as e:
        flash(f"Error al cambiar estado: {str(e)}", "error")
    
    return redirect(url_for('gestion_usuarios'))
@app.route('/noticias')
@login_required
def ver_noticias():
    noticias = Noticias.select(Noticias, Usuarios).join(Usuarios).order_by(Noticias.fecha_noticia.desc())
    return render_template('news/noticias.html', noticias=noticias)
    
@app.route('/noticias/nueva', methods=['GET', 'POST'])
@login_required
def crear_noticia():
    if request.method == 'POST':
        titulo = request.form['titulo']
        contexto = request.form['contexto']
        imagen = request.files.get('imagen')
        imagen_nombre = None
        
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imagen_nombre = filename

        if not titulo or not contexto:
            flash("Todos los campos son obligatorios", "error")
            return redirect(url_for('crear_noticia'))

        Noticias.create(
            titulo=titulo,
            contexto=contexto,
            imagen=imagen_nombre,
            autor=current_user,
            fecha_noticia=datetime.utcnow()
        )
        flash("Noticia publicada correctamente", "success")
        return redirect(url_for('ver_noticias'))

    return render_template('news/nueva_noticia.html')

@app.route('/noticias/eliminar/<int:noticia_id>', methods=['POST'])
@login_required
def eliminar_noticia(noticia_id):
    try:
        noticia = Noticias.get(Noticias.id_noticias == noticia_id)
        if noticia.autor != current_user:
            flash("No tienes permiso para eliminar esta noticia.", "error")
            return redirect(url_for('ver_noticias'))
        
        noticia.delete_instance()
        flash("Noticia eliminada correctamente", "success")
    except DoesNotExist:
        flash("La noticia no existe.", "error")
    except Exception as e:
        flash(f"Ocurrió un error: {e}", "error")
    
    return redirect(url_for('ver_noticias'))

@app.route('/noticias/modificar/<int:noticia_id>', methods=['GET', 'POST'])
@login_required
def modificar_noticia(noticia_id):
    try:
        noticia = Noticias.get(Noticias.id_noticias == noticia_id)
        
        if noticia.autor != current_user and current_user.rol.rol != 'Administrador':
            flash("No tienes permiso para modificar esta noticia.", "error")
            return redirect(url_for('ver_noticias'))
        
        if request.method == 'POST':
            titulo = request.form['titulo']
            contexto = request.form['contexto']
            imagen = request.files.get('imagen')
            
            if not titulo or not contexto:
                flash("Todos los campos son obligatorios", "error")
                return redirect(url_for('modificar_noticia', noticia_id=noticia_id))
            
            noticia.titulo = titulo
            noticia.contexto = contexto
            
            if imagen and allowed_file(imagen.filename):
                filename = secure_filename(imagen.filename)
                imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                noticia.imagen = filename
            
            noticia.save()
            flash("Noticia modificada correctamente", "success")
            return redirect(url_for('ver_noticias'))
        
        return render_template('news/modificar_noticia.html', noticia=noticia)
    except DoesNotExist:
        flash("La noticia no existe.", "error")
        return redirect(url_for('ver_noticias'))
    except Exception as e:
        flash(f"Ocurrió un error: {e}", "error")
        return redirect(url_for('ver_noticias'))

@app.route('/protected')
@login_required
def protected():
    return f"¡Hola, {current_user.email}! Esta es una página protegida. Tu ID es: {current_user.id_usuario}"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.before_request
def _db_connect():
    if db.is_closed():
        db.connect()

@app.teardown_request
def _db_close(exc):
    if not db.is_closed():
        db.close()

if __name__ == '__main__':
    app.run(debug=True)
