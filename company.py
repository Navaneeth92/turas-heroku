from flask import Blueprint, Flask, flash, request, jsonify, render_template,session,send_from_directory,redirect,url_for
import flask
import requests
import os
import shutil
import sqlite3
import uuid
import datetime
import jwt

from functools import wraps
from flask import current_app
#secret_key=current_app.config["SECRET_KEY"]
company_api = Blueprint('company_api', __name__)


conn_company = sqlite3.connect('company.db' , detect_types=sqlite3.PARSE_DECLTYPES,check_same_thread=False)

conn_jobs = sqlite3.connect('jobs.db' , detect_types=sqlite3.PARSE_DECLTYPES,check_same_thread=False)

conn_session = sqlite3.connect('session.db' , detect_types=sqlite3.PARSE_DECLTYPES,check_same_thread=False)

    	




def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        print(request.headers)
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401

        #try:
            # decoding the payload to fetch the stored details
        #print(token)
        try:
            data = jwt.decode(token, current_app.config["SECRET_KEY"],algorithms="HS256")
        except:
            return jsonify({'message' : 'Invalid Token'}), 401
        current_user=conn_company.execute('SELECT company_email FROM company_main WHERE public_id = "'+data['public_id']+'"').fetchone()
        if current_user==[]:
            return jsonify({'message' : 'Invalid User'}), 401
        
        return f(current_user, *args, **kwargs)

    return decorated



#tested
@company_api.route('/company_login', methods=['POST'])
def company_login():
    user_agent=str(request.headers.get('User-Agent'))
    headers_list = request.headers.getlist("HTTP_X_FORWARDED_FOR")
    http_x_real_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    ip_address = headers_list[0] if headers_list else http_x_real_ip
    datetime_now=datetime.datetime.now()

    user_session_data=conn_session.execute("SELECT * FROM UserSession where ip='"+ip_address+"' ORDER BY id DESC LIMIT 10;").fetchall()
    #print(user_session_data)
    if len(user_session_data)==10 and (datetime.datetime.now()-datetime.datetime.strptime(str(user_session_data[-1][6]), '%Y-%m-%d %H:%M:%S.%f')).seconds < 60:
      return jsonify({'data':'Too Many Attempts, Please wait for 1 Minute'}),429

    conn_session.execute("INSERT INTO UserSession(user,ip,user_agent,category,endpoint,datetime) values(?,?,?,?,?,?)" ,('',ip_address,user_agent,'company','/company_login',datetime_now))
    conn_session.commit() 

    try:
        data = request.form.to_dict(flat=False)
    except:
        return jsonify({'message' : 'Bad Request'}),400


    if data==None or not 'company_email' in data or not 'company_password' in data:
        return jsonify({'message' : 'Invalid Body'}),400

    company_email = data['company_email'][0]
    company_password = data['company_password'][0]



    company_details=conn_company.execute('SELECT * FROM company_main WHERE company_email = "'+company_email+'" LIMIT 1').fetchall()
    if company_details==[]:
        flash('Not registered, Please Register and Login',"info")
        return redirect(url_for('rec_register'))


    company_details=conn_company.execute('SELECT * FROM company_main WHERE company_email = "'+company_email+'" and company_password = "'+company_password+'" LIMIT 1').fetchall()
    if company_details==[]:
        flash('Official Email and Password enterred is invalid, please try again.',"info")
        return redirect(url_for('rec_login'))


    public_id = str(uuid.uuid4())
    
    payload = {'company_email':company_email, 'public_id':public_id,  'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60)}
    token=jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

    conn_company.execute("UPDATE company_main SET public_id='"+public_id+"' where company_email = '"+company_email+"'")
    conn_company.commit()

    conn_session.execute("UPDATE UserSession SET user='"+company_email+"' where ip = '"+ip_address+"' and datetime = '"+str(datetime_now)+"'")
    conn_session.commit()

    # response = flask.jsonify({'token':token})
    # response.headers.set('Content-Type', 'application/json')
    # return response, 200
    company_name = conn_company.execute('SELECT company_name FROM company_main WHERE company_email = "'+company_email+'" LIMIT 1').fetchone()
    flash('Login Successful',"info")
    return redirect(url_for('recruiter',company_name=company_name[0],_external=True))

@company_api.route('/company_update_token', methods=['POST'])
@token_required
def company_update_token(company_email):
    if company_email==None:
        return jsonify({'message' : 'Invalid Token'}), 401
    
    company_email=company_email[0]

    public_id = str(uuid.uuid4())

    payload = {'company_email':company_email, 'public_id':public_id,  'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes = 5)}
    token=jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")

    conn_company.execute("UPDATE company_main SET public_id='"+public_id+"' where company_email = '"+company_email+"'")
    conn_company.commit()

    return jsonify({'token':token})







#tested
@company_api.route('/company_register', methods=['POST'])
def company_register():
    try:
        data = request.form.to_dict(flat=False)
    except:
        flash('All fields are filled properly, Kindly check again.',"danger")
        return redirect(url_for('rec_register'))


    if data==None or not 'company_email' in data or not 'company_password' in data or not 'company_name' in data or not 'company_country' in data or not 'company_state' in data or not 'company_phone' in data or not 'company_total_employees' in data:
        flash('All fields are filled properly, Kindly check again.',"danger")
        return redirect(url_for('rec_register'))


    company_email = data['company_email'][0]
    
    company_details=conn_company.execute('SELECT * FROM company_main WHERE company_email = "'+company_email+'" LIMIT 1').fetchall()
    if company_details==[]:
        recruiter_name = data['recruiter_name'][0]
        company_name = data['company_name'][0]
        company_country = data['company_country'][0]
        company_city = data['company_state'][0]
        company_phone = data['company_phone'][0]
        company_total_employees = data['company_total_employees'][0]
        company_reg_id = data['company_reg_id'][0]
        company_password = data['company_password'][0]
        company_br_id = data['company_br_id'][0]
        company_website = data['company_website'][0]
        company_zip = data ['company_zip'][0]
        company_total_employees = data['company_total_employees'][0]
        

        conn_company.execute("INSERT INTO company_main(recruiter_name,company_name,company_country,company_city,company_phone,company_total_employees,company_reg_id,company_email,company_password,company_br_id,company_website,company_zip,datetime) values(?,?,?,?,?,?,?,?,?,?,?,?,?)" ,(recruiter_name,company_name,company_country,company_city,company_phone,company_total_employees,company_reg_id,company_email,company_password,company_br_id,company_website,company_zip,datetime.datetime.now()))
        conn_company.commit()    
        flash('Company has been registered succesfully, please login with official email address '+company_email,"success")
        return redirect(url_for('home'))

    else:
        flash('Company is already registerred, please login with official email address '+company_email,"info")
        return redirect(url_for('home'))




@company_api.route('/company_check_register', methods=['POST'])
def company_check_register():
    try:
        data = request.get_json()
    except:
        return jsonify({'message' : 'Bad Request'}),400


    if data==None or not 'company_email' in data:
        return jsonify({'message' : 'Invalid Body'}),400

    company_email=data['company_email']

    company_details=conn_company.execute('SELECT * FROM company_main WHERE company_email = "'+company_email+'" LIMIT 1').fetchall()
    if company_details==[]:
        return jsonify({'data':False}),404

    else:
        return jsonify({'data':True}),200








@company_api.route('/company_post_job', methods=['POST'])
@token_required
def company_post_job(company_email):
    if company_email==None:
        return jsonify({'message' : 'Invalid Token'}), 401
    company_email=company_email[0]

    try:
        data = request.get_json()
    except:
        return jsonify({'message' : 'Bad Request'}),400


    
    if data==None or not 'job_title' in data or not 'job_type' in data or not 'job_role' in data or not 'job_salary_range' in data or not 'job_skill' in data or not 'job_experience' in data or not 'job_location' in data or not 'job_description' in data:
        return jsonify({'message' : 'Invalid Body'}),400

    job_title = data['job_title']
    job_type = data['job_type']
    job_role = data['job_role']
    job_salary_range = data['job_salary_range']
    job_skill = data['job_skill']
    job_experience = data['job_experience']
    job_location = data['job_location']
    job_description = data['job_description']


    job_id=datetime.datetime.utcnow()


    conn_jobs.execute("INSERT INTO jobs_table(job_title,job_type,job_role,job_salary_range,job_skill,job_experience,job_location,job_description,company_email,job_id,datetime) values(?,?,?,?,?,?,?,?,?,?,?)" ,(job_title,job_type,job_role,job_salary_range,job_skill,job_experience,job_location,job_description,company_email,job_id,datetime.datetime.now()))
    conn_jobs.commit()    
    
    return jsonify({'data':'Job Posted Sucessfully'}),200




@company_api.route('/company_all_job', methods=['POST'])
@token_required
def company_all_job(company_email):
    if company_email==None:
        return jsonify({'message' : 'Invalid Token'}), 401
    company_email=company_email[0]

    job_details=conn_jobs.execute('SELECT job_title,job_role,job_experience,job_location FROM jobs_table WHERE company_email = "'+company_email+'"').fetchall()

    return jsonify({'data':job_details}),200






@company_api.route('/company_delete_posted_jobs', methods=['POST'])
@token_required
def company_delete_posted_jobs(company_email):
    if company_email==None:
        return jsonify({'message' : 'Invalid Token'}), 401
    company_email=company_email[0]

    try:
        data = request.get_json()
    except:
        return jsonify({'message' : 'Bad Request'}),400


    
    if data==None or not 'job_title' in data or not 'job_type' in data:
        return jsonify({'message' : 'Invalid Body'}),400


    job_type=data['job_type']
    job_title=data['job_title']

    try:
        conn_jobs.execute("DELETE from jobs_table where job_title = '"+job_title+"' and job_type = '"+job_type+"'")
        conn_jobs.commit()
        return jsonify({'msg':'Job Deleted Sucessfully.'}),200
    except:
        return jsonify({'msg':'Cannot Delete, Invalid Job Title or Type'}),404





