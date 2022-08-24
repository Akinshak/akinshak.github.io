from flask import Flask, render_template, request,url_for,redirect,flash,send_from_directory,session
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin,LoginManager,login_user,login_required,current_user,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine


app = Flask(__name__)


# CONFIGURE FLASK-APP TO USE FLASK-LOGIN 
# table creation in the DATABASE
login_manager = LoginManager()
login_manager.init_app(app)

# configuring the table
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))




# CREATING INSYDER DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///insyder.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
engine = create_engine("mysql+pymysql://user:pw@host/db", pool_pre_ping=True)


#CREATING A DATABASE(TABLE) FOR THE REGISTRATION(SIGN UP) PROCESS
# registeration table
class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer,nullable=False, primary_key=True)
    firstname = db.Column(db.String(40), nullable = False)
    lastname = db.Column(db.String(40), nullable = False)
    email = db.Column(db.String(40),nullable = False, primary_key=True, unique=True)
    password = db.Column(db.String(30),nullable=False)
db.session.autoflush = True
db.create_all()


# new_user = User(firstname="",lastname="",email="",password="")
# db.session.add(new_user)
# db.session.commit()

# THE SECRET KEY TO ACTIVATE WTFORM
app.secret_key = "My-Name-is"

# INDEX ROUTE
@app.route("/")
def index_page():
    return render_template("home.html")



# REGISTER FORM INHERITANCE
# form for the registration process
class RegisterForm(FlaskForm):
    firstname = StringField(label='Firstname',validators=[DataRequired()])
    lastname = StringField(label='Lastname',validators=[DataRequired()])
    email = StringField(label='Email',validators=[DataRequired()])
    password = PasswordField(label='Password',validators=[DataRequired()])
    submit = SubmitField(label='Register')

#REGISTER ROUTE
@app.route('/register', methods=["GET", "POST"])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login_page'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            email=form.email.data,
           
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        db.session.flush()
        login_user(new_user)
        return redirect(url_for("secrets_page"))

    return render_template("register.html", form=form, current_user=current_user)





# LOGIN FORM INHERITANCE
# form for the login process
class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label= 'Password',validators=[DataRequired()])
    submit = SubmitField(label='Log In')

# LOGIN ROUTE
@app.route('/login', methods=["GET", "POST"])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login_page'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login_page'))
        else:
            login_user(user)
            return redirect(url_for('secrets_page'))
    return render_template("login.html", form=form, current_user=current_user)

     
@app.route("/secrets")
@login_required
def secrets_page():
    print(current_user.firstname)
    return render_template("welcome.html", name=current_user.firstname ,current_user=current_user)



    
if __name__ == "__main__":
    app.run(debug=True)

# https://python.plainenglish.io/implementing-flask-login-with-hash-password-888731c88a99