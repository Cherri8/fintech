from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from sha import sha256
from datetime import datetime
import os
import re
import pandas as pd
from termcolor import colored
import time
import pyotp
import pyqrcode
from PIL import Image
from lsfr import generateID
from secret import generateSecret
from aes import encrypt as aes_encryption, decrypt as aes_decryption
import base64
import io
import csv

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-here'  # Required for session management
CORS(app)

# Database paths
database_dir = os.path.join(os.path.dirname(__file__), 'database')
USER_PATH = os.path.join(database_dir, 'user.txt')
HISTORY_PATH = os.path.join(database_dir, 'history.txt')

def get_key():
    with open('secret_key.txt', 'r') as file_obj:
        return file_obj.readline().strip()

def match(file_name, username, pin=None, opt='LOGIN'):
    try:
        print(f"Match function called: username={username}, opt={opt}")
        with open(file_name, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                try:
                    parts = line.strip().split('|')
                    if len(parts) >= 5 and parts[0] == username:  # Username is first field
                        print(f"Found user record: {parts}")
                        if opt == 'LOGIN':
                            return 1  # Found the user
                        elif opt == 'PIN':
                            if not pin:
                                print("PIN is None")
                                return 0
                            stored_pin = parts[4].strip()  # PIN is 5th field
                            print(f"PIN comparison for {username}:")
                            print(f"  Entered PIN (type={type(pin)}): '{pin}'")
                            print(f"  Stored PIN (type={type(stored_pin)}): '{stored_pin}'")
                            if pin == stored_pin:
                                print("PIN match successful")
                                return 1
                            else:
                                print("PIN mismatch")
                                return 0
                except Exception as parse_error:
                    print(f"Error parsing line: {str(parse_error)}")
                    continue
        print(f"User {username} not found in file")
        return 0
    except Exception as e:
        print(f"Error in match function: {str(e)}")
        return 0

def fetchSalt(file_name, username):
    try:
        with open(file_name, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 7 and parts[0] == username:
                    return parts[5]  # Salt is in 6th position
        print(f"User {username} not found in fetchSalt")
        return None
    except Exception as e:
        print(f"Error in fetchSalt: {str(e)}")
        return None

def fetchSecret(file_name, username):
    try:
        with open(file_name, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 7 and parts[0] == username:
                    return parts[6]  # Secret is in 7th position
        print(f"No secret found for user {username}")
        return None
    except Exception as e:
        print(f"Error in fetchSecret: {str(e)}")
        return None

def isGA(file_name, username):
    try:
        with open(file_name, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 8 and parts[0] == username:
                    return int(parts[7])  # 2FA status is in 8th position
        print(f"No 2FA status found for user {username}")
        return 0
    except Exception as e:
        print(f"Error in isGA: {str(e)}")
        return 0

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            pin = data.get('pin')
        else:
            username = request.form.get('username')
            pin = request.form.get('pin')
        
        if not username or not pin:
            response = {'success': False, 'message': 'Please provide both username and PIN'}
            return jsonify(response) if request.is_json else redirect(url_for('login_page'))

        if match(USER_PATH, username, opt='LOGIN'):
            if match(USER_PATH, username, pin, opt='PIN'):
                session['username'] = username
                # Check if 2FA is enabled
                if isGA(USER_PATH, username):
                    session['2fa_pending'] = True
                    session['2fa_verified'] = False
                    response = {
                        'success': True,
                        'requires_2fa': True,
                        'redirect': url_for('verify_2fa_page', username=username)
                    }
                else:
                    session['2fa_verified'] = True
                    response = {'success': True, 'redirect': url_for('dashboard')}
                return jsonify(response) if request.is_json else redirect(response['redirect'])
            else:
                response = {'success': False, 'message': 'Invalid PIN'}
                return jsonify(response) if request.is_json else redirect(url_for('login_page'))
        else:
            response = {'success': False, 'message': 'User not found'}
            return jsonify(response) if request.is_json else redirect(url_for('login_page'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    pin = data.get('pin')
    phone = data.get('phone')

    if not all([username, password, email, pin, phone]):
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

    if not pin.isdigit() or len(pin) != 6:
        return jsonify({'status': 'error', 'message': 'PIN must be 6 digits'}), 400

    # Check if username already exists
    try:
        with open(USER_PATH, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 1 and parts[0] == username:
                    return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

        # Generate salt and hash password
        salt = generateSecret()
        hashed_password = sha256(password + salt)
        secret = generateSecret()  # For 2FA

        # Save user data with | separator
        with open(USER_PATH, 'a') as write_obj:
            user_data = f"{username}|{email}|{hashed_password}|{phone}|{pin}|{salt}|{secret}|0\n"
            write_obj.write(user_data)
            print(f"Registered user data: {user_data.strip()}")

        return jsonify({'status': 'success', 'message': 'Registration successful'})
    except Exception as e:
        print(f"Error during registration: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Registration failed'}), 500

@app.route('/api/balance/<username>', methods=['GET'])
def get_balance(username):
    balance = 0
    try:
        with open(HISTORY_PATH, 'r') as read_obj:
            next(read_obj)  # Skip header
            for line in read_obj:
                parts = line.strip().split('#')
                if len(parts) < 3:  # Skip invalid entries
                    continue
                    
                if parts[2] == 'TOP_UP' and len(parts) >= 5:
                    if parts[4] == username:  # User is recipient
                        balance += float(parts[3])  # Amount
                elif parts[2] == 'TRANSFER' and len(parts) >= 7:
                    amount = float(parts[3])  # Amount
                    if parts[4] == username:  # User is sender
                        balance -= amount
                    elif parts[6] == username:  # User is recipient
                        balance += amount
                            
        return balance
    except Exception as e:
        print(f"Error calculating balance: {e}")
        return 0

@app.route('/api/topup', methods=['POST'])
def topup():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401
    
    data = request.json
    amount = data.get('amount')
    bank = data.get('bank', 'Bank Transfer')
    
    if not amount:
        return jsonify({'status': 'error', 'message': 'Amount is required'}), 400
    
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
    
    username = session['username']
    
    # Record top-up transaction
    now = datetime.now()
    date = now.strftime('%Y-%m-%d')
    time_str = now.strftime('%H:%M:%S')
    
    with open(HISTORY_PATH, 'a') as f:
        f.write(f'{date}#{time_str}#TOP_UP#{amount}#{username}#-#-\n')
    
    new_balance = get_balance(username)
    return jsonify({
        'status': 'success', 
        'message': f'Top-up of {amount} successful',
        'new_balance': new_balance
    })

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    username = session['username']
    data = request.json
    recipient_phone = data.get('recipient_phone')
    amount = float(data.get('amount', 0))
    pin = data.get('pin')
    
    print(f"Transfer request received:")
    print(f"  From: {username}")
    print(f"  Amount: {amount}")
    print(f"  To phone: {recipient_phone}")
    print(f"  PIN provided: {bool(pin)}")
    
    if not recipient_phone:
        return jsonify({'status': 'error', 'message': 'Recipient phone number is required'}), 400
    
    if not amount or amount <= 0:
        return jsonify({'status': 'error', 'message': 'Invalid amount'}), 400
    
    if not pin:
        return jsonify({'status': 'error', 'message': 'PIN is required'}), 400
    
    # Verify PIN
    if not match(USER_PATH, username, str(pin), 'PIN'):  # Convert PIN to string
        print(f"PIN verification failed for user {username}")
        return jsonify({'status': 'error', 'message': 'Invalid PIN'}), 401
    
    # Check current balance
    current_balance = get_balance(username)
    if amount > current_balance:
        return jsonify({'status': 'error', 'message': 'Insufficient funds'}), 400
    
    # Validate recipient
    recipient_found = False
    recipient_username = None
    
    try:
        print(f"Looking for recipient with phone: {recipient_phone}")
        with open(USER_PATH, 'r') as read_obj:
            for line in read_obj:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 4 and parts[3] == recipient_phone:  # Phone is in 4th position
                    print(f"Found matching phone number for user: {parts[0]}")
                    if parts[0] == username:  # Check if trying to transfer to self
                        return jsonify({'status': 'error', 'message': 'Cannot transfer to yourself'}), 400
                    recipient_found = True
                    recipient_username = parts[0]
                    break
        
        if not recipient_found:
            print(f"No user found with phone number: {recipient_phone}")
            return jsonify({'status': 'error', 'message': 'Recipient not found'}), 404
        
        # Record the transaction
        now = datetime.now()
        date = now.strftime('%Y-%m-%d')
        time_str = now.strftime('%H:%M:%S')
        
        # Record sender's transaction (negative amount)
        with open(HISTORY_PATH, 'a') as write_obj:
            write_obj.write(f'{date}#{time_str}#TRANSFER#{amount}#{username}#{recipient_username}#{recipient_username}\n')
        
        # Record recipient's transaction (positive amount)
        with open(HISTORY_PATH, 'a') as write_obj:
            write_obj.write(f'{date}#{time_str}#TRANSFER#{amount}#{recipient_username}#{username}#{recipient_username}\n')
        
        # Get updated balance
        new_balance = get_balance(username)
        
        return jsonify({
            'status': 'success',
            'message': 'Transfer successful',
            'new_balance': new_balance,
            'recipient': recipient_username
        })
        
    except Exception as e:
        print(f"Transfer error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An error occurred during transfer'}), 500

@app.route('/api/transactions/<username>', methods=['GET'])
def get_transactions(username):
    try:
        transactions = []
        with open(HISTORY_PATH, 'r') as read_obj:
            next(read_obj)  # Skip header line
            for line in read_obj:
                if username in line:
                    parts = line.strip().split('#')
                    if len(parts) >= 4:
                        date, time, description, amount = parts[0], parts[1], parts[2], parts[3]
                        # For top-up, user is always receiver
                        if description == "Top Up":
                            tx_type = 'credit'
                        else:
                            tx_type = 'credit' if parts[-1] == username else 'debit'
                        
                        transactions.append({
                            'date': f"{date} {time}",
                            'description': description,
                            'amount': amount,
                            'type': tx_type
                        })
        
        return jsonify({
            'status': 'success',
            'transactions': sorted(transactions, key=lambda x: x['date'], reverse=True)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    if session.get('2fa_pending', False) and not session.get('2fa_verified', False):
        return redirect(url_for('verify_2fa_page', username=session['username']))
    
    username = session['username']
    balance = get_balance(username)
    
    # Get transaction history
    transactions = []
    try:
        with open(HISTORY_PATH, 'r') as read_obj:
            next(read_obj)  # Skip header
            for line in read_obj:
                parts = line.strip().split('#')
                if len(parts) >= 5 and (parts[4] == username or (len(parts) >= 7 and parts[6] == username)):
                    date_time = parts[0] + ' ' + parts[1]
                    description = parts[2]
                    amount = float(parts[3])
                    
                    if description == "TRANSFER":
                        if len(parts) >= 7 and parts[6] == username:
                            description = f"Received from {parts[5]}"
                        else:
                            description = f"Sent to {parts[6] if parts[6] != 'None' else 'Unknown'}"
                            amount = -amount
                    
                    transactions.append({
                        'date': date_time,
                        'description': description,
                        'amount': amount
                    })
    except Exception as e:
        print(f"Error fetching transactions: {str(e)}")
    
    return render_template('dashboard.html', 
                         username=username, 
                         balance=balance,
                         transactions=sorted(transactions, key=lambda x: x['date'], reverse=True))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/setup-2fa/<username>')
def setup_2fa(username):
    try:
        if 'username' not in session or session['username'] != username:
            return redirect(url_for('login_page'))
        
        print(f"Setting up 2FA for user: {username}")
        secret = fetchSecret(USER_PATH, username)
        
        if not secret:
            print(f"No secret found for user: {username}")
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        print(f"2FA secret retrieved for user: {username}")
        return render_template('setup_2fa.html', 
                             username=username, 
                             secret=secret)
    except Exception as e:
        print(f"Error in setup_2fa: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error setting up 2FA'}), 500

@app.route('/enable-2fa/<username>', methods=['POST'])
def enable_2fa(username):
    try:
        if 'username' not in session or session['username'] != username:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
        print(f"Enabling 2FA for user: {username}")
        code = request.json.get('code')
        secret = fetchSecret(USER_PATH, username)
        
        if not code or not secret:
            print(f"Invalid request: code={bool(code)}, secret={bool(secret)}")
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            print(f"2FA code verified for user: {username}")
            # Update user's 2FA status
            updated = False
            with open(USER_PATH, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            for line in lines:
                if not line.strip():
                    continue
                if username in line:
                    parts = line.strip().split('|')
                    if len(parts) >= 8:
                        parts[7] = '1'  # Enable 2FA
                        new_line = '|'.join(parts) + '\n'
                        new_lines.append(new_line)
                        updated = True
                        print(f"Updated 2FA status for user {username}")
                    else:
                        print(f"Invalid user record format: {line.strip()}")
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            if not updated:
                print(f"User record not found for {username}")
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
            with open(USER_PATH, 'w') as f:
                f.writelines(new_lines)
            
            print(f"2FA enabled successfully for {username}")
            return jsonify({'status': 'success', 'message': '2FA enabled successfully'})
        
        print(f"Invalid 2FA code for user: {username}")
        return jsonify({'status': 'error', 'message': 'Invalid code'}), 400
        
    except Exception as e:
        print(f"Error enabling 2FA: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error enabling 2FA'}), 500

@app.route('/verify-2fa/<username>')
def verify_2fa_page(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login_page'))
    
    if not session.get('2fa_pending', False):
        return redirect(url_for('dashboard'))
    
    return render_template('verify_2fa.html', username=username)

@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    try:
        print(f"2FA verification attempt for {username}")
        print(f"Session state: {session}")
        
        if 'username' not in session or session['username'] != username:
            print(f"Unauthorized 2FA attempt for {username}")
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        
        if not session.get('2fa_pending'):
            print(f"No 2FA pending for {username}")
            return jsonify({'status': 'error', 'message': 'No 2FA verification pending'}), 400
        
        code = request.json.get('code')
        secret = fetchSecret(USER_PATH, username)
        
        print(f"Verifying 2FA code for {username}:")
        print(f"  Code provided: {bool(code)}")
        print(f"  Secret found: {bool(secret)}")
        
        if not code or not secret:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            session['2fa_verified'] = True
            session.pop('2fa_pending', None)
            print(f"2FA verification successful for {username}")
            return jsonify({
                'status': 'success',
                'message': '2FA verification successful',
                'redirect_url': '/dashboard'
            })
        
        print(f"Invalid 2FA code for {username}")
        return jsonify({'status': 'error', 'message': 'Invalid code'}), 400
        
    except Exception as e:
        print(f"Error in 2FA verification: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error during 2FA verification'}), 500

@app.route('/download-transactions/<format>')
def download_transactions(format):
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    username = session['username']
    transactions = []
    
    # Read transactions
    try:
        with open(HISTORY_PATH, 'r') as read_obj:
            next(read_obj)  # Skip header
            for line in read_obj:
                parts = line.strip().split('#')
                if len(parts) >= 5 and (parts[4] == username or (len(parts) >= 7 and parts[6] == username)):
                    date_time = parts[0] + ' ' + parts[1]
                    description = parts[2]
                    amount = float(parts[3])
                    
                    if description == "TRANSFER":
                        if len(parts) >= 7 and parts[6] == username:
                            description = f"Received from {parts[5]}"
                        else:
                            description = f"Sent to {parts[6] if parts[6] != 'None' else 'Unknown'}"
                            amount = -amount
                    
                    transactions.append({
                        'Date': date_time,
                        'Description': description,
                        'Amount': amount
                    })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # Sort transactions by date
    transactions = sorted(transactions, key=lambda x: x['Date'], reverse=True)
    
    if format == 'csv':
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['Date', 'Description', 'Amount'])
        writer.writeheader()
        writer.writerows(transactions)
        
        response = app.make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=transactions_{username}.csv'
        return response
    
    elif format == 'excel':
        df = pd.DataFrame(transactions)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Transactions', index=False)
            
            # Get the xlsxwriter workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Transactions']
            
            # Add some cell formats
            money_fmt = workbook.add_format({'num_format': '#,##0.00'})
            date_fmt = workbook.add_format({'num_format': 'yyyy-mm-dd hh:mm:ss'})
            
            # Set column widths and formats
            worksheet.set_column('A:A', 20)  # Date column
            worksheet.set_column('B:B', 30)  # Description column
            worksheet.set_column('C:C', 15, money_fmt)  # Amount column
        
        output.seek(0)
        response = app.make_response(output.getvalue())
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        response.headers['Content-Disposition'] = f'attachment; filename=transactions_{username}.xlsx'
        return response
    
    return jsonify({'status': 'error', 'message': 'Invalid format'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
