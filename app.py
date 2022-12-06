from email import message
from flask import Flask, render_template, request, url_for, flash, g, redirect, session
import sqlite3
from datetime import date

import random
import string
import hashlib
import binascii

app_info = {
    'db_file' : 'C:/Users/Lukar/Desktop/Python/Flask/Interface/data/cantor.db'
}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SECRETKEY123'

# Datebase connection
def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close


class Currency:
    def __init__(self,code, name, flag):
        self.code = code
        self.name = name
        self.flag = flag
    
    def __repr__(self) -> str:
        return '<Currency {}>'.format(self.code)

class CantorOffer:
    def __init__(self):
        self.currencies=[]
        self.denied_code = []

    def load_offer(self):
        self.currencies.append(Currency('USD','Dollar','flag_usa.png'))
        self.currencies.append(Currency('EUR','Euro','flag_europe.png'))
        self.currencies.append(Currency('JPY','Yen','flag_japan.png')) 
        self.denied_code.append('USD')                                 
                                         
    def get_by_code(self,code):
        for currency in self.currencies:
            if currency.code == code:
                return currency
        return Currency('unknown', 'unknown','flag_pirat.png')


class UserPass:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        os_urandom_static = b'\x90qj\xc6\x8e\x8bF\xe0 \tea\xb4<@\x9b\xca\x0c\xe7%z\xcfUj\n\xc1_\xa5\xe0%\x06r\xe6\x0f\xb1\x08\x9fg\x14\xc8\x14\xf9\xf7\xf3X\xde\r\x9d;BU\xe4\x8d\xcf\xd4\xcc{\x1a\xa2\xb8'
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters
        random_password = ''.join(random.choice(password_characters)for i in range(3))
        self.password = random_password

    def login_user(self):

        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?;'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()

        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where name = ?;'
        cur = db.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user == None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user['is_active']!=1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']
        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']


@app.route('/init_app')
def init_app():
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admin = cur.fetchone()

    if active_admin!=None and active_admin['cnt']>0:
        flash('App is already set-up!')
        return redirect(url_for('index'))
    
    user_pass = UserPass()
    user_pass.get_random_user_password()
    sql_statement = 'insert into users(name, email, password, is_active, is_admin) values(?,?,?,True,True)'
    db.execute(sql_statement,[user_pass.user, 'asd@asd.pl', user_pass.hash_password()])
    db.commit()
    flash(f'Username: {user_pass.user}\nPassword: {user_pass.password}')

    return redirect(url_for('index'))


@app.route('/exchange', methods=['GET', 'POST'])
def exchange():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))
    

    offer = CantorOffer()
    offer.load_offer()
    if request.method == 'GET':
        return render_template('exchange.html', active_menu='exchange', offer=offer, login=login)
    else:
        currency = 'EUR'
        if 'currency' in request.form:
            currency = request.form['currency']
        
        amount = 100
        if 'amount' in request.form:
            amount = request.form['amount']

        if currency in offer.denied_code:
            flash('The currency {} cannot be accepted'.format(currency))
        elif offer.get_by_code(currency) == 'unknow':
            flash('The selected currency is unknow')
        else:
            db = get_db()
            sql_command = "insert into transactions(currency, amount, user) values(?, ?, ?);"
            db.execute(sql_command, [currency, amount, 'admin'])
            db.commit()
            flash('Request was accepted!')

    return render_template('exchange_resault.html', active_menu='exchange', currency=currency, amount=amount, login=login)     

@app.route('/')
def index():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return render_template('index.html', active_menu='index', login=login)

@app.route('/history')
def history():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    sql_command='select id,currency,amount,trans_date from transactions;'
    cur= db.execute(sql_command)
    transactions = cur.fetchall()

    return render_template('history.html', active_menu='history', transactions=transactions, login=login)

@app.route('/delete_transaction/<int:transation_id>')
def delete_transaction(transation_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    db = get_db()
    sql_command = 'delete from transactions where id = ?;'
    db.execute(sql_command, [transation_id])
    db.commit()

    return redirect(url_for('history'))


@app.route('/edit_transaction/<int:transation_id>', methods=['GET', 'POST'])
def edit_transaction(transation_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    offer = CantorOffer()
    offer.load_offer()
    db = get_db()

    if request.method == 'GET':
        sql_statement = 'select id, currency, amount from transactions where id = ?;'
        cur = db.execute(sql_statement, [transation_id])
        transaction = cur.fetchone()

        if transaction == None:
            flash('No such transaction!')
            return redirect(url_for('history'))
        else:
            return render_template('edit_transaction.html', transaction=transaction, offer=offer, active_menu='history', login=login)
    else:
        currency = 'EUR'
        if 'currency' in request.form:
            currency = request.form['currency']
        
        amount = 100
        if 'amount' in request.form:
            amount = request.form['amount']

        if currency in offer.denied_code:
            flash('The currency {} cannot be accepted'.format(currency))
        elif offer.get_by_code(currency) == 'unknow':
            flash('The selected currency is unknow')
        else:
            db = get_db()
            sql_command = "update transactions set currency=?,amount=?,user=?,trans_date=? where id = ?;"
            db.execute(sql_command, [currency, amount, 'admin', date.today(), transation_id])
            db.commit()
            flash('Request was accepted!')

    return redirect(url_for('history'))

@app.route('/login', methods=['GET', 'POST'])
def login():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Login succesfull')
            return redirect(url_for('index'))
        else:
            flash('Login failed! Try again!')
            return render_template('login.html', active_menu='login', login=login)
    
@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out')
    return redirect(url_for('login'))

@app.route('/users')
def users():
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_statement = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_statement)
    users = cur.fetchall()

    return render_template('users.html', active_menu='users', users=users, login=login)
    


@app.route('/user_status_change/<action>/<user_name>', methods=['GET', 'POSET'])
def user_status_change(action, user_name):
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()

    if action == 'active':
        sql_statement = 'update users set is_active = (is_active + 1) % 2 where name=? and name <> ?;'
        db.execute(sql_statement, [user_name, login.user])
        db.commit()
    
    elif action == 'admin':
        sql_statement = 'update users set is_admin = (is_admin + 1) % 2 where name=? and name <> ?;'
        db.execute(sql_statement, [user_name, login.user])
        db.commit()

    return redirect(url_for('users'))

@app.route('/delete_user/<user_name>')
def delete_user(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_command = 'delete from users where name = ? and name <> ?;'
    db.execute(sql_command, [user_name, login.user])
    db.commit()

    return redirect(url_for('users'))

@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user, login=login)
    else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']
        user['email'] = '' if not 'email' in request.form else request.form['email']

        if user['user_name'] == '':
            message = 'Name cannot be empty!'
        elif user['user_pass'] == '':
            message = 'Password cannot be empty!'
        elif user['email'] == '':
            message = 'Email cannot be empty!'
    
    if not message:
        user_pass = UserPass(user['user_name'], user['user_pass'])
        sql_statement = 'insert into users(name, email, password, is_active, is_admin) values(?,?,?,True,True)'
        db.execute(sql_statement,[user_pass.user, user['email'], user_pass.hash_password()])
        db.commit()
        flash(f'Username: {user_pass.user}\nPassword: {user_pass.password}')
        return redirect(url_for('index'))
    else:
        flash('Correct error: {}'.format(message))
        return render_template('new_user.html', active_menu='users', user=user, login=login)
    

if __name__ == '__main__':
    app.run()
