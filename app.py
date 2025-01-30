import bcrypt
from flask import Flask, render_template, request, redirect, session, flash, url_for
import logging
from flask_mysqldb import MySQL

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


app = Flask(__name__)

app.secret_key = "your_secret_key"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'memoir'

mysql = MySQL(app)

@app.route("/")
def index():
    logger.debug("Rendering index page")
    return render_template("index.html")


@app.route("/signin", methods=["POST", "GET"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode('utf-8')

        logger.debug(f"Signin attempt with email: {email}")

        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT id, password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
        except Exception as e:
            logger.error(f"Database error during signin: {e}")
            flash("An error occurred during login. Please try again.", "danger")
            return redirect(url_for('signin'))
        finally:
            cur.close()

        if user and bcrypt.checkpw(password, user[1].encode('utf-8')):  # user[1] is the hashed password
            session['user_id'] = user[0]  # Store user ID (integer) in session
            logger.info(f"User {email} logged in successfully with ID {user[0]}")
            flash('Login successful', 'success')
            return redirect(url_for('my_journal'))
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            flash('Invalid username or password', 'danger')

    return render_template("signin.html")



@app.route("/signup", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        Username = request.form["Username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        logger.debug(f"Signup attempt with Username: {Username}, Email: {email}")

        if password != confirm_password:
            logger.warning("Passwords do not match during signup.")
            flash('Passwords do not match', 'danger')
            return redirect(url_for("signup"))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logger.debug(f"Password hashed successfully for {email}")

        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT id FROM users WHERE Username = %s OR email = %s", (Username, email))
            existing_user = cur.fetchone()

            if existing_user:
                logger.warning(f"User already exists with Username: {Username} or Email: {email}")
                flash('Username or email already exists', 'danger')
                return redirect(url_for("signup"))

            cur.execute("INSERT INTO users (Username, email, password) VALUES (%s, %s, %s)", 
                        (Username, email, hashed_password.decode('utf-8')))
            mysql.connection.commit()
            logger.info(f"User {Username} registered successfully.")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('signin'))
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            flash("An error occurred. Please try again.", 'danger')
        finally:
            cur.close()

    return render_template("signup.html")

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/my_journal')
def my_journal():
    if 'user_id' not in session:
        flash('Please log in to view your journal.', 'info')
        return redirect(url_for('signin'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, title, content, created_at FROM journal_entries WHERE user_id = %s", (session['user_id'],))
    entries = cur.fetchall()
    cur.close()

    return render_template('my_journal.html', entries=entries)

@app.route('/new_entry', methods=['GET', 'POST'])
def new_entry():
    user_id = session.get('user_id')
    if not user_id or not isinstance(user_id, int):
        flash('Please log in to create a journal entry.', 'info')
        return redirect(url_for('signin'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        # Debugging statement
        print("Inserting entry for user ID:", user_id)

        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO journal_entries (user_id, title, content) VALUES (%s, %s, %s)", 
                        (user_id, title, content))
            mysql.connection.commit()
            flash('Journal entry created successfully!', 'success')
        except Exception  as e:
            flash('Error: User does not exist. Please log in again.', 'danger')
            return redirect(url_for('signin'))
        finally:
            cur.close()

        return redirect(url_for('my_journal'))

    return render_template('new_entry.html')


@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    if 'user_id' not in session:
        flash('Please log in to edit a journal entry.', 'info')
        return redirect(url_for('signin'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, title, content FROM journal_entries WHERE id = %s AND user_id = %s", 
                (entry_id, session['user_id']))
    entry = cur.fetchone()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        cur.execute("UPDATE journal_entries SET title = %s, content = %s WHERE id = %s AND user_id = %s", 
                    (title, content, entry_id, session['user_id']))
        mysql.connection.commit()
        cur.close()

        flash('Journal entry updated successfully!', 'success')
        return redirect(url_for('my_journal'))

    cur.close()
    return render_template('edit_entry.html', entry=entry)


@app.route('/delete_entry/<int:entry_id>')
def delete_entry(entry_id):
    if 'user_id' not in session:
        flash('Please log in to delete a journal entry.', 'info')
        return redirect(url_for('signin'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM journal_entries WHERE id = %s AND user_id = %s", (entry_id, session['user_id']))
    mysql.connection.commit()
    cur.close()

    flash('Journal entry deleted successfully!', 'success')
    return redirect(url_for('my_journal'))




if __name__ == "__main__":
    app.run(debug=True)
