from flask import * 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt

#create app
app=Flask(__name__,static_folder="public",static_url_path="/")
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///user.db'
app.secret_key="mykey"
bcrypt=Bcrypt(app)

db=SQLAlchemy(app)
app.app_context().push()

# Initialize LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    

#forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class DestinationForm(FlaskForm):
    name = StringField('Destination Name', validators=[DataRequired()])
    submit = SubmitField('Create Destination')


#home
@app.route("/")
def index():
     if current_user.is_authenticated:
        return redirect(url_for('destination'))
     else:
         return render_template("base.html")

#login
@app.route("/login",methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for("destination"))
    return render_template("login.html",form=form)


@app.route("/logout",methods=['GET','POST'])
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect (url_for('login'))

#register
@app.route("/register",methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html",form=form)
    
@app.route("/destination", methods=['GET', 'POST'])
@login_required
def destination():
    form = DestinationForm()
    if form.validate_on_submit():
        new_destination = Destination(name=form.name.data)
        db.session.add(new_destination)
        db.session.commit()
        flash('Destination created successfully!', 'success')
        return redirect(url_for('destination'))  # Refresh the page to show updated list
    
    # Fetch the list of all destinations
    destinations = Destination.query.all()
    return render_template('destination.html', form=form, destinations=destinations)

    

        
if __name__ == "__main__":
    app.run()

