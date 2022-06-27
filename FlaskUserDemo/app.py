import pymysql, uuid, os, hashlib, random
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
app = Flask(__name__)

# Register the setup page and import create_connection()
from utils import create_connection, setup
app.register_blueprint(setup)

@app.before_request
def restrict():
    restricted_pages = ['list_users', 'view_user', 'edit', 'delete', 'borrow', 'delete_movie', 'view_user_movies', 'view_all_user_movies']
    if 'logged_in' not in session and request.endpoint in restricted_pages:
        flash("Please log in.")
        return redirect('/login')

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        password = request.form['password']
        encrypted_password = hashlib.sha256(password.encode()).hexdigest()

        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = """SELECT * FROM users WHERE email = %s AND password = %s"""
                values = (
                    request.form['email'],
                    encrypted_password
                    )
                cursor.execute(sql, values)
                result = cursor.fetchone()
                connection.commit()
        if result:
            session['logged_in'] = True
            session['first_name'] = result['first_name']
            session['role'] = result['role']
            session['id'] = result['id']
            flash("You have logged in.")
            return redirect('/')  
        else:
            messages = ['Invalid username or password.', 'you cannot', 'Try again in !̶̡̽͆@̷̬̠̹̔#̸̝͖̝͝E̷̤̊͒͠Ŗ̵̗͐͝R̶̨̉Ō̵̤͗R̶͕̩̆#̵̡̩̹͐@̴̯̾!̷͇̒͂͠ seconds.', 'Pro Tip: Type the CORRECT username and password.', 'ẽ̵̡̛̞̤̠͙̘̖̑͗̐̍̾͑̒̄́͗͆͗͒͒̚͝ͅͅv̵̡̗͈́̀̾̄̌̋̿̎̎̅̀̏̌͝ȩ̵̛̛̺͖͍̥̞̣͓̭̫͎̱̦͉͍̣̮̝̩̍̅͝r̷̛̳͇̥̙͍̫͉͉̠͓̙̼͎͉̻̪̹̮̻̰̣̦͎̠̓̂͌͐̏̑̋̄̾̏̉͆͐̓̐͋͛̈͂̄͐̚̕̕̚ý̸̡̘̳̊̀͋̓̆̋̚ ̴̧̨͔̙͕̻͕̮̬̮̯̼̗͖̩͋͂̊̏̆̏͗͂̃̔̌̊̉̓̂̋͂̑̒̉͆̈̈́͘̚͘͜͠ͅş̸̡̛̼̗̙̳͔͔̺̩͕̖̭̱̰̥̹͚̲͈̺͔͕̲͎͕͗̊ͅẽ̷̛̛̤͍̯̬̝̺͉͈̜̝͓̘̖̤͈̬͈̄̓̅͜c̴̡̡̛̛̛͇̺̙͉͓͙͇͙̹͕͈̥̏͆̄̀̾̄̊̏͒̾̅́̈͆̋͘͜͠͝͝o̶̧̪̟̣̺̜̺͇̣̫͍͗̑͝ͅń̶̡̛̛͔̱̫͖̞͕͚̺̪̗̰̜͚̙̪̫̥͇̲̳͙̠̱̪͇̇͗̀͊̑̌̆̃̈̾̂̚͘̚̕ͅd̸̛̤̟̝̺͇͉̥̯͚͖̠̯̑̅̎̾͒̎̍̈́̔̒̂͛̽͛̅̊͛̾̊̉̕̚͝͝͠ ̷̛̦͔͓̰͕̰͚̭̦̗̮̠̙̫̝͎̟̱̘͔̥͖͈̥͖̣̓̂̀͂̌̂̀̃̊͛́̈͗̄̌͊̃̌̓̀͊͘̚͝y̸̨͖͖̝͙̗̬̝͕͙͗̿́̀̐͂̇̃̽̈́̑̋͘͘̚͘͘ö̸̢̺̝̣̮̬̮͓͚͍̥̰̮̲͚͉̥́́́̈́ư̸̟̤̣͓̪̜͖̗̇̇́̎̀͛̉̔͗̄͐͆͛̈̋̓̋̽͘͘͠͠ ̸̡̦͕̯̣̀͊̈́̂̓̈́̎͜͝á̵̛̜͉̱̲͎̼̘̥͔̖͕̠̳̟̰̺̯͕̯̼͊͐́͐̓͛̇̆̇̏̽͋̇͆̈́͑͊͑̆̈́̑̚͘͝͝ŗ̴̢̡̧̮̫̩̦̹̱̖̮͈̠̳͕̝̟͇͔͐̾̓̌̒̋̀̈́̈́̔̄ͅḛ̶̡̧̛̠͔̟͖͎̯̯̟̩͇̘̜͔̹̼̖̥̳̈́͂͐͂͊͛̍̆̀̒̅͌͗̿̂͌̀̃̆͘͠͝ ̴̛̞̣̭̪͙̤͕͕̠̣̮̖̲͙͓͈̠͔͙̝̇̃̂̐̀̆̂̽͗̈́̐͘͘̚͠ͅn̷̤̼̹̟̟̓̈́́͋̈́͂̈̈́̎̅̋̈͑͐͐͘͠ợ̷̣͛̉͛͂̌͊̂̉̂̀̐̈́́͛̂̄̕̕͝͝͝͝t̴̛̟͖͚̹̖̺̺͍͓̅͂̑̈́̂̏̒͂̅̊́͊̋̽̓̈́̇̀͘͘ ̴̢̢̮̪̤̩̞̤͈̯̪̘̦̯̫̲̼̪͚̲͍͖͔̗͒̕r̶̢̧̨̭̝͔̝̬̲͖̮͍̜̣͙̻͉̫̱̲̻͔͕̹̗͍̖̓̀̈́̍̈́͗͋͌̀̓́͠ǘ̷͍̰̺͕̹̱̤̰̮̎̈͗̎̔̂͂͠ņ̸̨̬̘̝̝͚̠̼̺͎̹̗̗̪͕͉̱̭̱̝̱͓͈̝̈́͗̃̃̏̌͜͝ņ̴͉͙̖̮̖̻̮͇̘̰͖̙̮̆̔͛̊̃̈́̎̅͒̒͛͘͝͝͠i̵̦͓̭̭͗̈́͛͌͌͌̐͐̀̂͒̏̎̓́̈́͐̆̂͆͆͑̐̕͝ņ̷̧̢̛̣̗͔̮̬̠̱̲͖̩͎̬͙̻̰̖͓̯̯͌̓̎̓̄̌̔̀̐͘͜g̴̨̛̛̝̣̫̝͓̼̘͍̜̬̝̻̜̟̳̹̭̞̍͂̀͐͒̄̐͜ͅ,̴̛̭̝̎̋̂̔̓͗̆̌͊̀͌ͅ ̷̨̧̢̭̘̰͙̟̳̭̫̯̟̗͚̣̺̘̂̒̈́̈͋̎̈̈́́͌̿̿̈͛̑̈́̓͝͝ỉ̶̢̧̡̧̛͉͉͉̻̜͔͇̲͕͍̙̺̱͖͔̙̺̓̓̓͑͐̎̀͜͝͝ͅͅ ̶̨͎̞͎̫̘̖̮̰͒̊̊̂̿̍̊͘ā̶̧̢͇͉̙͍̩̳̦̟̬̟̟̝̦̹̟͈̗͇̦͍̺̓̔̍̏̈́̔͘͘͝m̶̡̢̭̫̟͖̻̩͍̥̞̹̞͉͚̫̪̲̦̭̗͈͈͐͐̄́̋͗͆͊̏̔̈͌̆̋̂̂͛͛̀̿͋̂͘͝͠ͅ ̷̢̢̳͍̫̀̐̈́̈́͌̅͂̔̈́͌̀̈́̌̽̋̈́̀͐͌̀͜ͅḡ̶̨̧̢̡̤͇̪̠͙̭̙̟̹̭̼̖̠͈̳̪̳͙̰̻̘͎̰͋̂̃̓̃̾̚͠͝e̴̹̗̓̍̋̔̈́͌̇͑̓͊̒̋̋̈́̽̔̽͝͝ͅṫ̴̢̼̬̺̣̭͓̤̞͙̒͛͋͐̏̓̌͋̌͂́̿͜͝ͅt̶̢̧̻͉̥͓̹̹̫͈̻̻͔̹̲̜͊̈́̾̊̾̐̏̐͗̎̿̔̈̅͗̊̉̓͂̚͜͜͠ͅͅì̵̡̡̨͎̝͍͇̮̦̖̜̙̰̞̱̮͚̔̃̀͆̍̅͜ͅṉ̶̯͚̞͙͚̣͊̈́͜͝g̷̨͖̼̹̟̘͓̣̻̫̱̤̎͋̉̂̋͌̆͛̎̿͗̈́͗̑͜͝͝ ̶̨̨̛̬̖̟̝̼̗̖͕̭̀̿̍́̏̑̋͒́̈́́̔̓̀̃̊̎́́͗̕͜ͅc̶̡̧̡̡̛̤͉̺̯̙͚̱̘͇̟̮̳̮͔͓̦̄̓̿̀̇͆̆́͑̓̈́̌̑̀̊̀̒͘̚̚̕͜͜͝͝͝l̸̛̛͔̐̿̀̈́͌̎͑̋̇̋̓͆̎͗̀̄͝͝o̸̧̢̧͕̥̮̯̥̹͕̼̮̗̪͊̌͊͜ͅs̷͔͖̼̳̪̪̭͓͓͈̩̻͔̦͆̊̉̕͝ę̶̛̩̟̹̩̪͍͕͙̰̙̖̯̫̟̥̯͚̫͓̤̹̥͕́̏͋̐͆̉̇̾͑̿̆̌̃̅̃̅͑̆́̕̚͜͠ͅŗ̸̡̜̰̮̫̦̱͙̰͓͔̱̺̭̟̐̽̉͂̊̒̉̎͆̔̒́̈́̓̚̕̚']
            flash (messages[random.randint(0,4)])
            session['id'] = 0
            return redirect('/login')            
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect('/')

# TODO: Add a '/register' (add_user) route that uses INSERT
@app.route('/register', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':

        password = request.form['password']
        encrypted_password = hashlib.sha256(password.encode()).hexdigest()

        if request.files['avatar'].filename:
            avatar_image = request.files["avatar"]
            ext = os.path.splitext(avatar_image.filename)[1]
            avatar_filename = str(uuid.uuid4())[:8] + ext
            avatar_image.save("static/images/" + avatar_filename)
        else:
            avatar_filename = None

        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = """INSERT INTO users (first_name, last_name, email, password, avatar)
                VALUES (%s, %s, %s, %s, %s)
                """
                values = (
                    request.form['first_name'],
                    request.form['last_name'],
                    request.form['email'],
                    encrypted_password,
                    avatar_filename
                    )

                try:
                    cursor.execute(sql, values)
                    result = cursor.fetchone()
                    connection.commit()
                except pymysql.err.IntegrityError:
                    flash ("An account with that email is already in use. Try logging in.")
                    return redirect('/register')

                sql = """SELECT * FROM users WHERE email = %s AND password = %s"""
                values = (
                    request.form['email'],
                    encrypted_password
                    )
                cursor.execute(sql, values)
                result = cursor.fetchone()
                connection.commit()
        if result:
            session['logged_in'] = True
            session['first_name'] = result['first_name']
            session['role'] = result['role']
            session['id'] = result['id']
            flash("You have logged in.")
            return redirect('/')
    return render_template('users_add.html')

@app.route('/checkemail')
def check_email():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """SELECT * FROM users WHERE email = %s"""
            values = (request.args['email'])
            cursor.execute(sql, values)
            result = cursor.fetchone()
            connection.commit()
    if result:
        return jsonify({ 'status': 'Error' })
    else:
        return jsonify({ 'status': 'OK' })

# TODO: Add a '/dashboard' (list_users) route that uses SELECT
@app.route('/dashboard')
def list_users():
    if session['role'] != 'admin':
        flash("Access Denied.")
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            result = cursor.fetchall()
    return render_template('users_list.html', result=result)

# TODO: Add a '/profile' (view_user) route that uses SELECT
@app.route('/profile')
def view_user():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """SELECT * FROM users WHERE id = %s"""
            values = (request.args['id'])
            cursor.execute(sql, values)
            result = cursor.fetchone()
            connection.commit()
    return render_template('users_profile.html', result=result)

# TODO: Add a '/delete_user' route that uses DELETE
@app.route('/delete_user')
def delete():
    if session['role'] != 'admin' and str(session['id']) != request.args['id']:
        flash("Access Denied.")
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """DELETE FROM users WHERE id = %s"""
            values = (request.args['id'])
            cursor.execute(sql, values)
            connection.commit()
    flash("g̷̨̛̞͉̥̹͈̩̥̦͎̔͂̉̇̂̅̌̀͝o̷̢̡̲̠̟̪̻̬̝͙̥̫͍̥͗͌̈̔̋̂͐͋͛͊̌̈͆͝n̸͓̣͈͐ę̴͓͓̰̥̫̔̉")
    return redirect('/')

# TODO: Add an '/edit_user' route that uses UPDATE
@app.route('/edit_user', methods=['GET', 'POST'])
def edit():
    if session['role'] != 'admin' and str(session['id']) != request.args['id']:
        flash("Access Denied.")
        return abort(404)

    if request.method == 'POST':

        if request.files['avatar'].filename:
            avatar_image = request.files["avatar"]
            ext = os.path.splitext(avatar_image.filename)[1]
            avatar_filename = str(uuid.uuid4())[:8] + ext
            avatar_image.save("static/images/" + avatar_filename)
            if request.form['old_avatar'] != 'None':
                os.remove("static/images/" + request.form['old_avatar'])
        else:
            avatar_filename = None

        with create_connection() as connection:
            with connection.cursor() as cursor:
                if request.form['password']:

                    password = request.form['password']
                    encrypted_password = hashlib.sha256(password.encode()).hexdigest()

                    sql = """UPDATE users SET
                        first_name = %s,
                        last_name = %s,
                        email = %s,
                        password = %s,
                        avatar = %s
                        WHERE id = %s"""
                    values = (
                        request.form['first_name'],
                        request.form['last_name'],
                        request.form['email'],
                        encrypted_password,
                        avatar_filename,
                        request.form['id']
                    )
                else:
                    sql = """UPDATE users SET
                        first_name = %s,
                        last_name = %s,
                        email = %s,
                        avatar = %s
                        WHERE id = %s"""
                    values = (
                        request.form['first_name'],
                        request.form['last_name'],
                        request.form['email'],
                        avatar_filename,
                        request.form['id']
                    )
                cursor.execute(sql, values)
                connection.commit()
        return redirect('/profile?id=' + request.form['id'])
    else:
        with create_connection() as connection:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE id = %s"
                values = (request.args['id'])
                cursor.execute(sql, values)
                result = cursor.fetchone()
        return render_template('users_edit.html', result=result)

# <== SUBJECTS ==>
@app.route('/subjects_list')
def list_subjects():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM subjects")
            result = cursor.fetchall()
    return render_template('subjects_list.html', result=result)

@app.route('/delete_subject')
def delete_subject():
    if session['role'] != 'admin':
        flash("Access Denied.")
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """DELETE FROM subjects WHERE id = %s"""
            values = (request.args['id'])
            try:
                cursor.execute(sql, values)
                connection.commit()
            except pymysql.err.IntegrityError:
                sql = """DELETE FROM student_subjects WHERE subjectid = %s"""
                sql1 = """DELETE FROM subjects WHERE id = %s"""
                values = (request.args['id'])
                values1 = (request.args['id'])
                cursor.execute(sql, values)
                cursor.execute(sql1, values1)
                connection.commit()
    flash("g̷̨̛̞͉̥̹͈̩̥̦͎̔͂̉̇̂̅̌̀͝o̷̢̡̲̠̟̪̻̬̝͙̥̫͍̥͗͌̈̔̋̂͐͋͛͊̌̈͆͝n̸͓̣͈͐ę̴͓͓̰̥̫̔̉")
    return redirect('/')

@app.route('/select_subject')
def select():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """SELECT
	                    users.first_name, subjects.name 
                    FROM
	                    student_subjects
	                    JOIN 
		                    users ON student_subjects.userid = users.id
	                    JOIN
		                    subjects ON student_subjects.subjectid = subjects.id
                        WHERE users.id = %s"""
            values = (session['id'])
            cursor.execute(sql, values)
            result = cursor.fetchall()
            if len(result) < 5:
                sql = """INSERT INTO student_subjects (userid, subjectid)
                    VALUES (%s, %s)"""
                values = (
                    session['id'],
                    request.args['id']
                    )
                try:
                    cursor.execute(sql, values)
                    connection.commit()
                except pymysql.err.IntegrityError:
                    flash('You have already chosen this subject.')
                    return redirect('/subjects_list')
            else:
                flash('You already have 5 subjects. Edit your profile to remove a subject first.')
                return redirect('/subjects_list')
    flash('Subject selected.')
    return redirect('/')

@app.route('/deselect_subject')
def deselect():
    if str(session['id']) != request.args['id']:
        flash("Access Denied.")
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """DELETE FROM student_subjects WHERE subjectid = %s AND userid = %s"""
            values = (
                request.args['id'], 
                session['id']
                      )
            cursor.execute(sql, values)
            connection.commit()
    flash("g̷̨̛̞͉̥̹͈̩̥̦͎̔͂̉̇̂̅̌̀͝o̷̢̡̲̠̟̪̻̬̝͙̥̫͍̥͗͌̈̔̋̂͐͋͛͊̌̈͆͝n̸͓̣͈͐ę̴͓͓̰̥̫̔̉")
    return redirect('/')

@app.route('/subjects_selected')
def view_user_subjects():
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """SELECT
	                    users.first_name, subjects.name, subjects.HOF, subjects.faculty 
                    FROM
	                    student_subjects
	                    JOIN 
		                    users ON student_subjects.userid = users.id
	                    JOIN
		                    subjects ON student_subjects.subjectid = subjects.id
                        WHERE users.id = %s"""
            values = (session['id'])
            cursor.execute(sql, values)
            result = cursor.fetchall()
            connection.commit()
    return render_template('subjects_selected.html', result=result)

@app.route('/subjects_selected_admin')
def view_all_user_subjects():
    if session['role'] != 'admin':
        flash("Access Denied.")
        return abort(404)
    with create_connection() as connection:
        with connection.cursor() as cursor:
            sql = """SELECT
	                    users.id, users.first_name, users.last_name, subjects.name, subjects.HOF, users.year_level 
                    FROM
	                    student_subjects
	                    JOIN 
		                    users ON student_subjects.userid = users.id
	                    JOIN
		                    subjects ON student_subjects.subjectid = subjects.id"""
            cursor.execute(sql)
            result = cursor.fetchall()
            connection.commit()
    return render_template('subjects_selected_admin.html', result=result)

if __name__ == '__main__':
    import os

    # This is required to allow flashing messages. We will cover this later.
    app.secret_key = os.urandom(32)

    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)
