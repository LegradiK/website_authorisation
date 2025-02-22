from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE


class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Flask Login manager for restricting /secrets page
# only logged in users can access
login_manager = LoginManager()
login_manager.init_app(app)
# this should take 'str' ID of a user
# returns the corresponding user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template("index.html", logged_in=True)
    return render_template("index.html")


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        if db.session.query(User).filter(User.email == email).first():
            flash("This email is already registered. Please login instead.", "error")
            return redirect(url_for('login'))
        password = request.form.get('password')
        new_user = User(
            name = request.form.get('name'),
            email = email,
            password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
        )
        db.session.add(new_user)
        db.session.commit()
        flash("You've registered successfully!", "info")
        login_user(new_user, remember=True)
        return redirect(url_for('secrets', name=new_user.name))
    return render_template("register.html")


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user_email = request.form.get('email')
        user_password = request.form.get('password')
        user_data = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        if user_data == None:
            flash("This email doesn't exist in the database", "error")
            return redirect(url_for('login'))
        if check_password_hash(user_data.password, user_password):
            login_user(user_data, remember=True)
            flash("Password matched.", "info")
            print(user_data.name)
            return redirect(url_for('secrets', name=user_data.name))
        flash("Invalid password. Please try again", "error")
        return redirect(url_for('login'))
    return render_template("login.html")


@app.route('/secrets', methods=['GET'])
@login_required
def secrets():
    if current_user.is_authenticated:
        name = request.args.get('name')
        return render_template("secrets.html", name=name, logged_in=True)
    return redirect(url_for('login'))

@app.route('/download', methods=['GET'])
@login_required
def download():
    if current_user.is_authenticated:
        return send_from_directory(
            'static/files',
            'cheat_sheet.pdf',
            as_attachment = False,
        )
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    logout_user()
    flash("Logout successfully", "info")
    return redirect(url_for('home'))



if __name__ == "__main__":
    app.run(debug=True)
