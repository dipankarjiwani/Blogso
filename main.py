from flask import Flask, render_template, flash, redirect, request, url_for, session,logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextField, PasswordField, validators, TextAreaField
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# Config mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'dipmysql01'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


Articles = Articles()


# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    return render_template('articles.html', articles=Articles)


#  One particular Article
@app.route('/article/<string:ids>/')
def article(ids):
    return render_template('article.html', id=ids)


# Register form class
class RegisterForms(Form):
    name = StringField('Name',[validators.length(min=1, max=50)])
    username = StringField('Username', [validators.length(min=4, max=25)])
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForms(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s,%s,%s,%s)", (name,email,username,password))

        # Commit to Db
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can proceed to login','success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur =mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users where username =%s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passwords matched
                session['logged_in'] = True
                session['username'] = username

                flash('You are now Logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Password'
                return render_template('login.html', error=error)

            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html',error=error)

    return render_template('login.html')


# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


# Article form class
class ArticleForm(Form):
    title = StringField('Title', [validators.length(min=1, max=200)])
    body = TextAreaField('Body', [validators.length(min=30)])


# Add article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)