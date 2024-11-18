from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuración de la base de datos y claves
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '12345678'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Modelos de la base de datos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(50), nullable=False)

class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.String(200), nullable=True)
    fecha = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Rutas

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # Si el usuario ya está logueado, redirige al home
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validación simple
        if not username or not email or not password:
            flash('Todos los campos son obligatorios, we.', 'danger')
            return redirect(url_for('register'))

        # Comprobar si el usuario o email ya existe
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Ese nombre de usuario o correo ya existe.', 'danger')
            return redirect(url_for('register'))

        # Crear nuevo usuario
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Iniciar sesión automáticamente
        login_user(new_user)
        flash('Te registraste con éxito, ya estás logueado.', 'success')

        # Redirigir al home (dashboard o página principal)
        return redirect(url_for('home'))

    return render_template('register.html')  # Página de registro

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Si el usuario ya está logueado, redirige al home
        return redirect(url_for('welcome'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()  # Obtener el usuario

        if user and check_password_hash(user.password, password):  # Validar la contraseña
            login_user(user)  # Iniciar sesión
            flash('Has iniciado sesión exitosamente', 'success')
            return redirect(url_for('welcome'))  # Redirige a la página de bienvenida

        else:
            flash('Nombre de usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')  # Página de login




     

@app.route("/welcome")
@login_required
def welcome():
    return render_template("welcome.html")  # Página de bienvenida

@app.route("/logout")
@login_required
def logout():
    logout_user()  # Cerrar sesión
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('home'))  # Redirige al home después de cerrar sesión

# Ruta para crear eventos
@app.route("/create_event", methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        
        # Crear el nuevo evento
        new_event = Events(titulo=titulo, descripcion=descripcion, user_id=current_user.id)
        db.session.add(new_event)
        db.session.commit()
        
        flash('Evento creado con éxito', 'success')
        return redirect(url_for('home'))
    
    return render_template('create_event.html')

# Ruta para mostrar todos los eventos
@app.route("/events")
def events():
    events = Events.query.all()  # Obtener todos los eventos
    return render_template('events.html', events=events)

# Inicialización del user_loader de Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == "__main__":
    app.run(debug=True)
