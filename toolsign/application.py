from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.secret_key = os.urandom(16)

db = SQLAlchemy(app)


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)


class Technician(db.Model):
    __tablename__ = 'technician'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    signouts = db.relationship('Signout', backref='technician', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Tool(db.Model):
    __tablename__ = 'tool'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_signed_out = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    signouts = db.relationship('Signout', backref='tool', lazy=True)


class Key(db.Model):
    __tablename__ = 'key'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    is_signed_out = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    signouts = db.relationship('Signout', backref='key', lazy=True)


class Signout(db.Model):
    __tablename__ = 'signout'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    tool_id = db.Column(db.Integer, db.ForeignKey('tool.id'))
    technician_id = db.Column(db.Integer, db.ForeignKey('technician.id'))
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'))
    date_out = db.Column(db.DateTime, nullable=False)
    date_returned = db.Column(db.DateTime)
    returned = db.Column(db.Boolean, default=False)


class ErrorLog(db.Model):
    __tablename__ = 'error_log'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)


@app.errorhandler(Exception)
def handle_exception(e):
    error_msg = str(e)
    error_log = ErrorLog(message=error_msg)
    db.session.add(error_log)
    db.session.commit()
    flash(error_msg)
    return redirect(url_for('error_page'))


@app.route('/error')
def error_page():
    errors = [flash_message for flash_message in session.get('_flashes', [])]
    return render_template('error.html', errors=errors)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'tech_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    tech_id = session['tech_id']
    tech = Technician.query.get(tech_id)

    if tech is None:
        flash('No tech found with the current tech_id')
        return redirect(url_for('error_page'))

    tech_signouts = tech.signouts

    if request.method == 'POST':
        tool_id = request.form.get('tool_id')
        key_id = request.form.get('key_id')
        if tool_id is not None:
            tool = Tool.query.get(tool_id)
            if tool.is_signed_out:
                flash('The tool is already signed out.')
                return redirect(url_for('error_page'))
            tool.is_signed_out = True
        if key_id is not None:
            key = Key.query.get(key_id)
            if key.is_signed_out:
                flash('The key is already signed out.')
                return redirect(url_for('error_page'))
            key.is_signed_out = True
        signout = Signout(technician_id=tech_id, tool_id=tool_id, key_id=key_id, date_out=datetime.now())
        db.session.add(signout)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('There was an error processing your request.')
            return redirect(url_for('error_page'))
        return redirect(url_for('home'))

    tools = Tool.query.filter_by(is_signed_out=False).all()
    keys = Key.query.filter_by(is_signed_out=False).all()
    signouts = Signout.query.filter_by(returned=False).all()
    return render_template('home.html', tech=tech, tools=tools, keys=keys, signouts=signouts, tech_signouts=tech_signouts)


@app.route('/add_group', methods=['GET', 'POST'])
@login_required
def add_group():
    if request.method == 'POST':
        name = request.form.get('name')
        if Group.query.filter_by(name=name).first():
            flash('The group already exists.')
            return redirect(url_for('error_page'))
        new_group = Group(name=name)
        db.session.add(new_group)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The group already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_group'))
    return render_template('add_group.html')


@app.route('/add_tool', methods=['GET', 'POST'])
@login_required
def add_tool():
    if request.method == 'POST':
        name = request.form.get('name')
        group_id = request.form.get('group_id')
        group = Group.query.get(group_id)
        if not group:
            flash('The group does not exist.')
            return redirect(url_for('error_page'))
        if Tool.query.filter_by(name=name, group_id=group_id).first():
            flash('The tool already exists in this group.')
            return redirect(url_for('error_page'))
        new_tool = Tool(name=name, group_id=group_id)
        db.session.add(new_tool)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The tool already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_tool'))
    groups = Group.query.all()
    return render_template('add_tool.html', groups=groups)


@app.route('/add_key', methods=['GET', 'POST'])
@login_required
def add_key():
    if request.method == 'POST':
        name = request.form.get('name')
        group_id = request.form.get('group_id')
        if Key.query.filter_by(name=name).first():
            flash('The key already exists.')
            return redirect(url_for('error_page'))
        new_key = Key(name=name, group_id=group_id)
        db.session.add(new_key)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('The key already exists.')
            return redirect(url_for('error_page'))
        return redirect(url_for('add_key'))
    groups = Group.query.all()
    return render_template('add_key.html', groups=groups)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        tech = Technician.query.filter_by(name=name).first()
        if tech and tech.check_password(password):
            session['tech_id'] = tech.id
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('error_page'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('tech_id', None)
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        if Technician.query.filter_by(name=name).first():
            flash('A technician with that name already exists. Please use a different name.')
            return redirect(url_for('error_page'))
        tech = Technician(name=name)
        tech.set_password(password)
        db.session.add(tech)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('A technician with that name already exists. Please use a different name.')
            return redirect(url_for('error_page'))
        flash('Account created successfully. Please login with your new account.')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/return_item', methods=['GET', 'POST'])
@login_required
def return_item():
    tech_id = session['tech_id']
    tech = Technician.query.get(tech_id)

    if tech is None:
        flash('No tech found with the current tech_id')
        return redirect(url_for('error_page'))

    # Only get the signouts that are not returned
    tech_signouts = [signout for signout in tech.signouts if not signout.returned]

    if request.method == 'POST':
        signout_id = request.form.get('signout_id')
        signout = Signout.query.get(signout_id)

        if signout is None:
            flash("Invalid signout ID.")
            return redirect(url_for('error_page'))

        if signout.technician_id != tech_id:
            flash("You cannot return a tool you didn't sign out.")
            return redirect(url_for('error_page'))

        signout.returned = True
        signout.date_returned = datetime.now()

        if signout.tool_id is not None:
            tool = Tool.query.get(signout.tool_id)
            tool.is_signed_out = False

        if signout.key_id is not None:
            key = Key.query.get(signout.key_id)
            key.is_signed_out = False

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('There was an error processing your request.')
            return redirect(url_for('error_page'))

        return redirect(url_for('return_item'))

    return render_template('return_item.html', tech=tech, tech_signouts=tech_signouts)




@app.route('/ui')
def ui():
    return render_template('ui.html')


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form.get('name')
        item_type = request.form.get('type')
        group_id = request.form.get('group_id')

        # Check if the item already exists in the specified group
        existing_item = None
        if item_type == 'tool':
            existing_item = Tool.query.filter_by(name=name, group_id=group_id).first()
        elif item_type == 'key':
            existing_item = Key.query.filter_by(name=name, group_id=group_id).first()

        if existing_item:
            flash(f"The {item_type} '{name}' already exists in this group.")
            return redirect(url_for('error_page'))

        # Create and add the new item
        if item_type == 'tool':
            new_item = Tool(name=name, group_id=group_id)
        elif item_type == 'key':
            new_item = Key(name=name, group_id=group_id)
        
        db.session.add(new_item)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(f"There was an error adding the {item_type}.")
            return redirect(url_for('error_page'))

        return redirect(url_for('add_item'))

    groups = Group.query.all()
    return render_template('add_item.html', groups=groups)


def add_default_tools_and_keys():
    default_tools = ['K400', 'Propress', 'Combustion Analyzer']
    default_keys = ['Canadian', 'Electra', 'OMA', 'Concordia', 'Vine']
    default_group = Group.query.filter_by(name="Default").first()
    
    if default_group is None:
        default_group = Group(name="Default")
        db.session.add(default_group)
        db.session.commit()
    
    for tool_name in default_tools:
        if not Tool.query.filter_by(name=tool_name).first():
            new_tool = Tool(name=tool_name, group_id=default_group.id)
            db.session.add(new_tool)
    
    for key_name in default_keys:
        if not Key.query.filter_by(name=key_name).first():
            new_key = Key(name=key_name, group_id=default_group.id)
            db.session.add(new_key)
    
    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_default_tools_and_keys()
        app.run(debug=True)
