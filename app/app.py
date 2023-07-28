from flask import Flask, request, render_template, url_for, redirect, session, make_response, send_from_directory,jsonify, flash, send_file
import bcrypt
import pymysql
import pandas as pd
from werkzeug.utils import secure_filename
import os
from flask_session import Session
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.static_folder = 'static'

# Configure Flask-Session to use server-side sessions
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'your_secret_key'  # Replace with your secret key
Session(app)

# Load the allowed matricules from the Excel file
allowed_matricules = pd.read_excel('allowed_matricules.xlsx', header=None)[0].tolist()

# Database connection details
db_connection = pymysql.connect(
    host='localhost',
    user='root',
    password='Qrmm8075@',
    database='app'
    )

db_cursor = db_connection.cursor()

# Custom decorator to check if the user is an admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is logged in and has the 'admin' role in the session
        if 'matricule' not in session:
            # If the user is not logged in, redirect to the login page
            return redirect(url_for('login'))

        # If the user is not an admin, check if the matricule exists in the 'admin' table
        matricule = session.get('matricule')
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE matricule = %s", (matricule,))
        admin_user = cursor.fetchone()

        if not admin_user:
            # If the matricule is not found in the 'admin' table, redirect to the login page
            cursor = db_connection.cursor()
            cursor.execute("SELECT * FROM users WHERE matricule = %s and role='technicien'", (matricule,))
            technicien_user = cursor.fetchone()
            if technicien_user:
                return redirect(url_for('technicien_home'))
            else:
                return redirect(url_for('home'))

        # User is an admin, grant access to the protected route
        return f(*args, **kwargs)

    return decorated_function

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        matricule = session.get('matricule')
        role = session.get('role')

        # Check if the user is an admin
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE matricule = %s", (matricule,))
        admin_user = cursor.fetchone()
        if admin_user:
            cursor.close()
            return redirect(url_for('admin_home'))

        # Check if the user is an agent
        if not admin_user:
            cursor.execute("SELECT * FROM users WHERE matricule = %s AND role = 'technicien'", (matricule,))
            technicien_user = cursor.fetchone()
            if technicien_user:
                # User is an agent, redirect to the agent home page
                cursor.close()
                return redirect(url_for('technicien_home'))
        matricule = session.get('matricule')
        if matricule is None:
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function

def technicien_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        matricule = session.get('matricule')
        role = session.get('role')

        # Check if the user is an admin
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE matricule = %s", (matricule,))
        admin_user = cursor.fetchone()
        if admin_user:
            cursor.close()
            return redirect(url_for('admin_home'))

        # Check if the user is an agent
        if not admin_user:
            cursor.execute("SELECT * FROM users WHERE matricule = %s AND role = 'agent'", (matricule,))
            agent_user = cursor.fetchone()
            if agent_user:
                # User is an agent, redirect to the agent home page
                cursor.close()
                return redirect(url_for('home'))
            return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['POST'])
def signup():
    if 'matricule' in session:
        return redirect(url_for('home'))
    # Retrieve form data
    matricule = request.form['matricule']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Perform data validation
    error_message = None

    # Check if the matricule is valid
    if int(matricule) not in allowed_matricules:
        error_message = 'Invalid matricule.'
    else:
        # Check if the matricule already exists in the database
        db_cursor.execute(f"SELECT * FROM users WHERE matricule = %s", (matricule,))
        existing_matricule = db_cursor.fetchone()
        if existing_matricule:
            error_message = 'Matricule already exists.'
        else:
            if len(password) < 8:
                error_message = 'Password should be at least 8 characters long.'
            elif not any(char.isdigit() for char in password):
                error_message = 'Password should contain at least one digit.'
            elif not any(char.isalpha() for char in password):
                error_message = 'Password should contain at least one letter.'
            elif not any(char.isupper() for char in password):
                error_message = 'Password should contain at least one uppercase letter.'
            elif not any(char.islower() for char in password):
                error_message = 'Password should contain at least one lowercase letter.'
            elif password != confirm_password:
                error_message = 'Password and confirmation password do not match.'
    # If there are any errors, render the signup.html template with error messages and form data
    if error_message:
        return render_template('signup.html', error_message=error_message, matricule=matricule, password=password, confirm_password=confirm_password)

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user information in the appropriate table
    sql = f"INSERT INTO users (matricule, password,role) VALUES (%s, %s, %s)"
    values = (matricule, hashed_password.decode('utf-8'),'agent')

    db_cursor.execute(sql, values)
    db_connection.commit()


    return render_template('login.html')

@app.route("/", methods=["POST", "GET"])
def login():
    # Check if the user is already logged in
    if 'matricule' in session and 'role' in session:
        matricule = session['matricule']
        role = session['role']

        # Check if the user is an admin
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE matricule = %s", (matricule,))
        admin_user = cursor.fetchone()

        if admin_user:
            # User is an admin, redirect to the admin home page
            cursor.close()
            return redirect(url_for('admin_home'))
        # Check if the user is an agent
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM users WHERE matricule = %s ", (matricule,))
        user=cursor.fetchone()
        cursor.close()
        if user['role'] == 'agent':
            return redirect(url_for('home'))
        elif user['role'] == 'technicien':
            return redirect(url_for('technicien_home'))

    error_message = None

    if request.method == "POST":
        matricule = request.form["matricule"]
        password = request.form["password"]

        cursor = db_connection.cursor()

        # Check if the matricule and password match an admin in the "admins" table
        cursor.execute("SELECT * FROM admin WHERE matricule = %s", (matricule,))
        existing_admin = cursor.fetchone()

        if existing_admin and bcrypt.checkpw(password.encode('utf-8'), existing_admin[2].encode('utf-8')):
            # Successful login for admin
            session['matricule'] = matricule
            return redirect(url_for('admin_home'))

        # If not an admin, check the "users" table for agent or technician login
        cursor.execute("SELECT * FROM users WHERE matricule = %s", (matricule,))
        existing_user = cursor.fetchone()

        if existing_user and bcrypt.checkpw(password.encode('utf-8'), existing_user[1].encode('utf-8')):
            # Successful login for agent or technician
            session['matricule'] = matricule
            role = existing_user[2]  # Assuming the role column is at index 2 in the query result

            if role == 'agent':
                return redirect(url_for('home'))  # Redirect to agent home page
            elif role == 'technicien':
                return redirect(url_for('technicien_home'))  # Redirect to technician home page
            else:
                # Unapproved user
                session['role'] = 'unapproved'
                error_message = "You are not approved yet."

        else:
            error_message = "Invalid matricule or password."

    # Handle GET request for login page
    return render_template('login.html', error_message=error_message)



# Route for separate admin registration page (not the same as the user signup page)
SECRET_CODE = "helloworld"  # Replace this with your actual secret code


@app.route('/admin_registration', methods=['GET', 'POST'])
def admin_registration():
    if request.method == 'POST':
        matricule = request.form['matricule']
        password = request.form['password']
        secret_code = request.form['secret_code']  # Add a new input field in the HTML form for the secret code

        # Check if the provided secret code matches the predefined code
        if secret_code != SECRET_CODE:
            return "Unauthorized. You don't have permission to register as an admin."

        # Hash the password (same as your previous code)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store admin information in the "admins" table
        sql = "INSERT INTO admin (matricule, password) VALUES (%s, %s)"
        values = (matricule, hashed_password.decode('utf-8'))

        db_cursor.execute(sql, values)
        db_connection.commit()

        # Redirect to the login page after successful admin registration
        return redirect(url_for('login'))

    return render_template('admin_registration.html')

@app.route('/admin_home')
@admin_required
def admin_home():
    # Retrieve data for agents and their interventions count
    db_cursor.execute("""
        SELECT matricule, COUNT(*) as intervention_count 
        FROM interventions 
        GROUP BY matricule
    """)
    agents = db_cursor.fetchall()

    # Retrieve data for technicians and their resolved interventions count
    db_cursor.execute("""
        SELECT matricule_technicien as matricule, COUNT(*) as resolved_count 
        FROM interventions 
        WHERE statut = 'Resolved' 
        GROUP BY matricule_technicien
    """)
    techniciens = db_cursor.fetchall()

    return render_template('admin_home.html', agents=agents, techniciens=techniciens)


@app.route('/ticket_admin', methods=['GET','POST'])
@admin_required
def ticket_admin():
    if request.method == 'GET':
        # Retrieve the query parameters from the URL
        n_intervention = request.args.get('nIntervention')
        matricule_technicien = request.args.get('matriculeTechnicien')

        conn = db_connection
        cursor = conn.cursor()
        cursor.execute(
            'SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier, matricule_technicien, date_intervention, date_cloture, solution, matricule FROM interventions WHERE n_intervention = %s',
            (n_intervention,))
        intervention_data = cursor.fetchone()
        cursor.close()

        # Convert the intervention_data tuple to a dictionary
        column_names = [desc[0] for desc in cursor.description]
        intervention_data_dict = dict(zip(column_names, intervention_data))

        return render_template('ticket_admin.html',nIntervention=n_intervention,
                           matriculeTechnicien=matricule_technicien, **intervention_data_dict)

    elif request.method=='POST':
        n_intervention = request.form.get('nIntervention')
        matricule_technicien = request.form.get('modalMatriculeTechnicien')

        # Check if the matricule exists in the users table with the role "technicien"
        cursor = db_connection.cursor()
        cursor.execute("SELECT * FROM users WHERE matricule = %s AND role = 'technicien'", (matricule_technicien,))
        technicien_user = cursor.fetchone()
        cursor.close()

        if technicien_user:
            # Update the interventions table with the new matricule_technicien
            cursor = db_connection.cursor()
            cursor.execute('UPDATE interventions SET matricule_technicien = %s WHERE n_intervention = %s',
                           (matricule_technicien, n_intervention))
            db_connection.commit()
            cursor.close()
            flash('Matricule updated successfully!', 'success')
            return redirect(url_for('assign_intervention'))
        else:
            flash('Error: The provided matricule does not exist or is not assigned as a technicien.', 'error')
            # If there's an error during the update, render the same ticket_admin.html page with the error message.
            conn = db_connection
            cursor = conn.cursor()
            cursor.execute(
                'SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier, matricule_technicien, date_intervention, date_cloture, solution, matricule FROM interventions WHERE n_intervention = %s',
                (n_intervention,))
            intervention_data = cursor.fetchone()
            cursor.close()

            # Convert the intervention_data tuple to a dictionary
            column_names = [desc[0] for desc in cursor.description]
            intervention_data_dict = dict(zip(column_names, intervention_data))

            assign_intervention_url = url_for('assign_intervention')

            return render_template('ticket_admin.html', nIntervention=n_intervention,
                                   matricule_technicien=matricule_technicien, **intervention_data_dict, assign_intervention_url=assign_intervention_url)

@app.route('/update_matricule', methods=['POST'])
@admin_required
def update_matricule():

    # Get the form data from the POST request
    n_intervention = request.form.get('nIntervention')
    matricule_technicien = request.form.get('matriculeTechnicien')

    # Check if the matricule exists in the users table with the role "technicien"
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users WHERE matricule = %s AND role = 'technicien'", (matricule_technicien,))
    technicien_user = cursor.fetchone()
    cursor.close()


    if technicien_user:
        # Update the interventions table with the new matricule_technicien
        cursor = db_connection.cursor()
        cursor.execute('UPDATE interventions SET matricule_technicien = %s WHERE n_intervention = %s',
                       (matricule_technicien, n_intervention))
        db_connection.commit()
        cursor.close()
        flash('Matricule updated successfully!', 'success')

        # Redirect to the assign_intervention page upon successful update
        return jsonify({'status': 'success'})
        return redirect(url_for('assign_intervention'))


    else:
        # If the matricule does not exist or is not assigned as a technicien, set the status to False
        flash('Error: The provided matricule does not exist or is not assigned as a technicien.', 'error')
        return jsonify({'status': 'error', 'message': 'Invalid matricule or not assigned as a technicien.'})



@app.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    if request.method == 'POST':
        data = request.get_json()
        matricule = data.get('matricule')
        new_role = data.get('role')

        # Update the user role in the database
        cursor = db_connection.cursor()
        cursor.execute('UPDATE users SET role = %s WHERE matricule = %s', (new_role, matricule))
        db_connection.commit()
        cursor.close()

        # Return a JSON response indicating success
        return jsonify({'success': True})

    elif request.method == 'GET':
        # Fetch data for users from the database
        cursor = db_connection.cursor()
        cursor.execute("SELECT matricule, role FROM users")
        data = cursor.fetchall()
        cursor.close()
        # Fetch data for agents from the users table
        cursor = db_connection.cursor()
        cursor.execute("SELECT matricule, role FROM users WHERE role = 'agent'")
        agents = cursor.fetchall()

        # Fetch data for technicians from the users table
        cursor.execute("SELECT matricule, role FROM users WHERE role = 'technicien'")
        technicians = cursor.fetchall()

        # Get the number of interventions for each agent
        agents_with_interventions = []
        for agent in agents:
            cursor.execute("SELECT COUNT(*) FROM interventions WHERE matricule = %s", (agent[0],))
            num_interventions = cursor.fetchone()[0]
            agents_with_interventions.append((agent[0], agent[1], num_interventions))

        # Get the number of interventions for each technician
        technicians_with_interventions = []
        for technician in technicians:
            cursor.execute("SELECT COUNT(*) FROM interventions WHERE matricule_technicien = %s", (technician[0],))
            num_interventions = cursor.fetchone()[0]
            technicians_with_interventions.append((technician[0], technician[1], num_interventions))

        cursor.close()

        # Pass the data to the template for rendering
        return render_template('users.html', agents=agents_with_interventions,
                               technicians=technicians_with_interventions, data=data)




@app.route('/intervention_admin')
@admin_required
def intervention_admin():

        conn = db_connection
        cursor = conn.cursor()
        cursor.execute('SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier, matricule_technicien, date_intervention, date_cloture, solution, matricule  FROM interventions')
        interventions = cursor.fetchall()
        cursor.close()
        modified_data = []
        for data_row in interventions:
            fichier_data = data_row[9]
            if fichier_data:
                # Assuming 'fichier' is stored as a BLOB in the database
                modified_row = (*data_row[:9], fichier_data, *data_row[10:])  # Replace the 9th element with the binary data
            else:
                modified_row = data_row
            modified_data.append(modified_row)

        return render_template('intervention_admin.html', interventions=modified_data)





@app.route('/accueil', methods=['GET', 'POST'])
@agent_required
def home():

    if request.method == 'GET':
        matricule = session.get('matricule')
        return render_template('accueil.html', matricule=matricule)

@app.route('/logout')
def logout():
    session.clear()

    # Create a response with no content, just to add headers to prevent caching
    response = make_response()
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response, 303, {'Location': url_for('login')}





@app.route('/technicien_home')
@technicien_required
def technicien_home():
    matricule_technicien = session.get('matricule')
    conn = db_connection
    cursor = conn.cursor()
    cursor.execute(
        'SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier,matricule_technicien, date_intervention, date_cloture, solution, matricule  FROM interventions where matricule_technicien=%s ORDER BY (statut="terminé")',
        (matricule_technicien,))
    data = cursor.fetchall()
    cursor.close()
    modified_data = []
    for data_row in data:
        fichier_data = data_row[9]
        if fichier_data:
            # Assuming 'fichier' is stored as a BLOB in the database
            modified_row = (*data_row[:9], fichier_data, *data_row[10:])  # Replace the 9th element with the binary data
        else:
            modified_row = data_row
        modified_data.append(modified_row)

    return render_template('technicien_home.html', data=modified_data)

@app.route('/ticket_technicien', methods=['GET', 'POST'])
@technicien_required
def ticket_technicien():
    if request.method == 'GET':
        # Retrieve the query parameters from the URL
        n_intervention = request.args.get('nIntervention')

        conn = db_connection
        cursor = conn.cursor()
        cursor.execute(
            'SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier, matricule_technicien, date_intervention, date_cloture, solution, matricule FROM interventions WHERE n_intervention = %s ',
            (n_intervention,))
        intervention = cursor.fetchone()
        cursor.close()

        # intervention contains valid data, you can access its elements safely
        date_intervention = intervention[11]
        date_cloture = intervention[12]

        formatted_date_intervention = date_intervention.strftime("%Y-%m-%d") if date_intervention else ""
        formatted_date_cloture = date_cloture.strftime("%Y-%m-%d") if date_cloture else ""

        return render_template('ticket_technicien.html', nIntervention=n_intervention, titre=intervention[1],
                               matricule=intervention[14], date_demande=intervention[2],
                               categorie=intervention[3], priorite=intervention[4],
                               statut=intervention[5], description=intervention[6],
                               emplacement=intervention[7], ressource=intervention[8],
                               fichier=intervention[9], matricule_technicien=intervention[10],
                               dateintervention=formatted_date_intervention, datecloture=formatted_date_cloture,
                               solution=intervention[13])

    elif request.method=='POST':
        n_intervention = request.form.get('nIntervention')
        date_intervention = request.form.get('dateintervention')
        date_cloture = request.form.get('datecloture')
        solution = request.form.get('solution')
        statut =request.form.get('statut')

        # Convert empty date fields to None (NULL)
        date_intervention = datetime.strptime(date_intervention, "%Y-%m-%d").date() if date_intervention else None
        date_cloture = datetime.strptime(date_cloture, "%Y-%m-%d").date() if date_cloture else None

        cursor = db_connection.cursor()
        cursor.execute(
            'UPDATE interventions SET date_intervention = %s, date_cloture = %s, solution = %s, statut = %s WHERE n_intervention = %s',
            (date_intervention, date_cloture, solution, statut, n_intervention))
        db_connection.commit()
        cursor.close()

        # Redirect to the technicien_home page upon successful update
        return redirect(url_for('technicien_home'))



@app.route('/signup', methods=['GET'])
def show_signup_form():
    if 'matricule' in session:
        return redirect(url_for('home'))
    return render_template('signup.html')



@app.route('/ticket', methods=['GET'])
@agent_required
def show_ticket():
    matricule = session.get('matricule')
    return render_template('ticket.html')

# Get the current directory
current_directory = os.path.dirname(os.path.abspath(__file__))
upload_directory = os.path.join(current_directory, 'uploads')
app.config['UPLOAD_FOLDER'] = upload_directory



@app.route('/ticket', methods=['POST'])

@agent_required
def ticket():
    # Extract form data and user matricule
    matricule = session.get('matricule')
    # Extract form data
    titre = request.form.get('titre')
    description = request.form.get('description')
    categorie = request.form.get('categorie')
    priorite = request.form.get('priorite')
    emplacement = request.form.get('emplacement')
    ressource = request.form.get('ressource')
    fichier = request.files.get('fichier')
    date_demande = datetime.now()
    filepath=''
    if fichier:
        # Securely save the uploaded file
        filename = secure_filename(fichier.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        fichier.save(filepath)
        # Read the file data in binary mode
        with open(filepath, 'rb') as file:
            fichier_data = file.read()
    else:
        fichier_data = b''
    # Insert form data into the MySQL table
    db_cursor.execute("""
        INSERT INTO interventions (matricule, titre, description, categorie, priorite, emplacement, ressource, fichier,date_demande)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (matricule, titre, description, categorie, priorite, emplacement, ressource, filepath,date_demande))
    db_connection.commit()
    return redirect(url_for('intervention'))

@app.route('/interventions', methods=['GET'])
@agent_required
def intervention():
    matricule = session.get('matricule')
    conn=db_connection
    cursor=conn.cursor()
    cursor.execute('SELECT n_intervention, titre, date_demande, categorie, priorite, statut, description, emplacement, ressource, fichier, matricule_technicien, date_intervention, date_cloture, solution  FROM interventions where matricule=%s', (matricule,))
    data=cursor.fetchall()
    cursor.close()
    modified_data = []
    for data_row in data:
        fichier_data = data_row[9]
        if fichier_data:
            # Assuming 'fichier' is stored as a BLOB in the database
            modified_row = (*data_row[:9], fichier_data, *data_row[10:])  # Replace the 9th element with the binary data
        else:
            modified_row = data_row
        modified_data.append(modified_row)

    return render_template('interventions.html',data=modified_data)


@app.route('/uploads/<filename>')
def upload_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.run(port=8080, debug=True)
